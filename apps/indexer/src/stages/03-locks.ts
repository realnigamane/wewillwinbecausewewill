/**
 * STAGE 3 — Lock analysis.
 *
 * This is where the tool earns its keep. "Locked liquidity" is not a field you
 * can read off a contract; it has to be reconstructed. The approach:
 *
 *   1. For every surviving pool, pull the complete ERC-20 Transfer history of
 *      its LP token via HyperSync (filtered to just those LP addresses).
 *   2. Replay the transfers to get exact LP balances per holder. This is exact,
 *      not sampled, and it costs one sweep regardless of holder count.
 *   3. Classify each holder:
 *        burned                   -> dead address, provably unrecoverable
 *        locker_known             -> address in our locker registry
 *        locker_unknown_contract  -> has bytecode; not withdrawable by a
 *                                    keyholder on a whim
 *        eoa                      -> a plain wallet; can rug at any time
 *   4. lockedFraction  = (burned + locked) / totalSupply
 *      lockedLiquidityUsd = totalLiquidityUsd * lockedFraction
 *
 * Step 3's contract-vs-EOA check is why this works without a perfect locker
 * registry. A hardcoded list of locker addresses will always miss the long tail
 * of 2020-2022 custom lockers; "does this address have code" never does.
 *
 * The user's actual target — dead memecoins whose dev rugged what they could
 * and left the locked remainder stranded — falls out of this directly: high
 * lockedFraction, low absolute USD, creation date years ago, zero recent volume.
 */
import { HypersyncClient, type LogField } from '@envio-dev/hypersync-client';
import { TOPIC_TRANSFER, BURN_ADDRESSES, LOCKERS } from '@liqarch/shared';
import type { MulticallEngine } from '../lib/multicall.js';
import type { ValuedPool, PoolWithLocks, HolderRecord } from '../lib/types.js';
import { logger } from '../lib/log.js';

const BURN_SET = new Set<string>(BURN_ADDRESSES.map((a) => a.toLowerCase()));
const LOCKER_MAP = new Map(LOCKERS.map((l) => [l.address.toLowerCase(), l]));

/**
 * Replay LP Transfer events to exact per-holder balances.
 *
 * Chunked by LP address because HyperSync's address filter is a set membership
 * test — passing 50k addresses at once produces an unwieldy request, while
 * chunks of ~2k stream comfortably.
 */
export async function reconstructLpHolders(
  pools: ValuedPool[],
  opts: { toBlock: number; chunkSize?: number; onProgress?: (done: number, total: number) => void },
): Promise<Map<string, Map<string, bigint>>> {
  const apiToken = process.env.ENVIO_API_TOKEN;
  if (!apiToken) throw new Error('ENVIO_API_TOKEN is required');

  const client = HypersyncClient.new({
    url: process.env.HYPERSYNC_URL ?? 'https://eth.hypersync.xyz',
    bearerToken: apiToken,
  });

  const chunkSize = opts.chunkSize ?? 2000;
  const balances = new Map<string, Map<string, bigint>>();
  for (const p of pools) balances.set(p.address, new Map());

  const addresses = pools.map((p) => p.address);
  let processed = 0;

  for (let i = 0; i < addresses.length; i += chunkSize) {
    const chunk = addresses.slice(i, i + chunkSize);

    const query: any = {
      fromBlock: 0,
      toBlock: opts.toBlock,
      logs: [{ address: chunk, topics: [[TOPIC_TRANSFER]] }],
      fieldSelection: {
        log: ['Address', 'Topic1', 'Topic2', 'Data'] as LogField[],
      },
    };

    const stream = await client.stream(query, {});
    try {
      for (;;) {
        const res = await stream.recv();
        if (res === null) break;

        for (const log of res.data?.logs ?? []) {
          const lp = (log.address ?? '').toLowerCase();
          const book = balances.get(lp);
          if (!book) continue;

          // Transfer is (from indexed, to indexed, value). Some non-standard
          // tokens emit it with fewer indexed args; those show up with a null
          // topic2 and we skip them rather than mis-attribute a balance.
          if (!log.topic1 || !log.topic2) continue;

          const from = ('0x' + log.topic1.slice(-40)).toLowerCase();
          const to = ('0x' + log.topic2.slice(-40)).toLowerCase();
          const value = BigInt(log.data && log.data !== '0x' ? log.data.slice(0, 66) : '0x0');
          if (value === 0n) continue;

          // Mint is from 0x0; we still record it as leaving the zero address so
          // that totals reconcile against totalSupply.
          book.set(from, (book.get(from) ?? 0n) - value);
          book.set(to, (book.get(to) ?? 0n) + value);
        }

        const next = res.nextBlock;
        if (next != null) {
          query.fromBlock = next;
          if (Number(next) >= opts.toBlock) break;
        }
      }
    } finally {
      await stream.close?.();
    }

    processed += chunk.length;
    opts.onProgress?.(processed, addresses.length);
    logger.debug(`lp holders: ${processed}/${addresses.length} pools replayed`);
  }

  return balances;
}

export async function analyzeLocks(
  mc: MulticallEngine,
  pools: ValuedPool[],
  balances: Map<string, Map<string, bigint>>,
  opts: { minLockedUsd: number },
): Promise<PoolWithLocks[]> {
  // Collect every non-burn, non-locker holder with a meaningful balance so we
  // can check them for bytecode in one batched pass.
  const unknownHolders = new Set<string>();

  for (const pool of pools) {
    const book = balances.get(pool.address);
    if (!book) continue;
    for (const [holder, bal] of book) {
      if (bal <= 0n) continue;
      if (BURN_SET.has(holder) || LOCKER_MAP.has(holder)) continue;
      // Only bother checking holders with >=1% of supply — below that the
      // classification can't move the headline number meaningfully.
      if ((bal * 100n) / pool.lpTotalSupply >= 1n) unknownHolders.add(holder);
    }
  }

  logger.info(`lock analysis: probing bytecode for ${unknownHolders.size.toLocaleString()} distinct holders`);
  const codeSizes = await mc.getCodeSizes([...unknownHolders]);

  const out: PoolWithLocks[] = [];

  for (const pool of pools) {
    const book = balances.get(pool.address);
    if (!book) continue;

    let burned = 0n;
    let lockedKnown = 0n;
    let lockedUnknownContract = 0n;
    const holders: HolderRecord[] = [];

    for (const [holder, bal] of book) {
      if (bal <= 0n) continue;

      let classification: HolderRecord['classification'];
      let lockerName: string | null = null;

      if (BURN_SET.has(holder)) {
        classification = 'burned';
        burned += bal;
      } else if (LOCKER_MAP.has(holder)) {
        const l = LOCKER_MAP.get(holder)!;
        classification = 'locker_known';
        lockerName = l.name;
        // Unverified registry entries are counted, but the UI shows them
        // separately so an address I got wrong can't quietly inflate the total.
        lockedKnown += bal;
      } else if ((codeSizes.get(holder) ?? 0) > 0) {
        classification = 'locker_unknown_contract';
        lockedUnknownContract += bal;
      } else {
        classification = 'eoa';
      }

      holders.push({
        holder,
        balance: bal,
        fraction: Number((bal * 1_000_000n) / pool.lpTotalSupply) / 1_000_000,
        classification,
        lockerName,
        unlockAt: null,
      });
    }

    const lockedTotal = burned + lockedKnown + lockedUnknownContract;
    const lockedFraction = Number((lockedTotal * 1_000_000n) / pool.lpTotalSupply) / 1_000_000;
    const lockedLiquidityUsd = pool.totalLiquidityUsd * lockedFraction;
    const burnedFraction = Number((burned * 1_000_000n) / pool.lpTotalSupply) / 1_000_000;

    if (lockedLiquidityUsd < opts.minLockedUsd) continue;

    holders.sort((a, b) => b.fraction - a.fraction);

    out.push({
      ...pool,
      lpBurned: burned,
      lpLockedKnown: lockedKnown,
      lpLockedUnknownContract: lockedUnknownContract,
      lockedFraction,
      lockedLiquidityUsd,
      burnedLiquidityUsd: pool.totalLiquidityUsd * burnedFraction,
      earliestUnlockAt: null,
      holders: holders.slice(0, 25), // top 25 is plenty for the detail view
      passesThreshold: true,
    });
  }

  logger.info(
    `lock analysis: ${out.length.toLocaleString()} pools clear $${opts.minLockedUsd} in locked liquidity`,
  );

  return out;
}
