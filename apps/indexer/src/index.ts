/**
 * Scan orchestrator.
 *
 *   pnpm scan                      full pre-2024 sweep
 *   pnpm scan --from 12000000      resume / partial range
 *   pnpm scan --min-usd 500        different threshold
 *   pnpm scan --skip-discovery     reuse data/pools.ndjson, re-run valuation only
 *   pnpm verify-lockers            sanity-check the locker registry on-chain
 *
 * Why the stage ordering is what it is
 * ------------------------------------
 * Discovery is one cheap sweep. Valuation is ~3 calls per pool. Lock analysis
 * is a full Transfer-history replay per pool — by far the most expensive step.
 * So we narrow aggressively before each escalation in cost:
 *
 *   ~1.2M discovered  ->  ~350k with a priceable quote side
 *                     ->  ~60k holding >= $100 total
 *                     ->  ~40k clearing $100 in LOCKED liquidity
 *
 * Running lock analysis on all 1.2M instead of the 60k survivors would take
 * roughly 20x longer for an identical answer.
 */
import 'dotenv/config';
import { readFileSync, existsSync, mkdirSync, createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { PRE_2024_END_BLOCK, LOCKERS } from '@liqarch/shared';
import { MulticallEngine } from './lib/multicall.js';
import { logger } from './lib/log.js';
import { discover } from './stages/01-discover.js';
import { valueV2Pools, getEthPriceUsd } from './stages/02-value.js';
import { reconstructLpHolders, analyzeLocks } from './stages/03-locks.js';
import { persist, startRun, finishRun, failRun } from './lib/db.js';
import type { DiscoveredPool } from './lib/types.js';

const args = process.argv.slice(2);
const cmd = args[0] ?? 'scan';
const flag = (name: string, dflt?: string) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : dflt;
};
const has = (name: string) => args.includes(`--${name}`);

const DATA_DIR = 'data';
const POOLS_FILE = `${DATA_DIR}/pools.ndjson`;

function rpcUrls(): string[] {
  const raw = process.env.RPC_URLS ?? '';
  const urls = raw.split(',').map((s) => s.trim()).filter(Boolean);
  if (urls.length === 0) {
    throw new Error('RPC_URLS is empty. Add at least one endpoint to .env (see .env.example).');
  }
  return urls;
}

async function readPools(path: string): Promise<DiscoveredPool[]> {
  const pools: DiscoveredPool[] = [];
  const rl = createInterface({ input: createReadStream(path), crlfDelay: Infinity });
  for await (const line of rl) {
    if (line.trim()) pools.push(JSON.parse(line));
  }
  return pools;
}

async function scan() {
  const t0 = Date.now();
  const endBlock = Number(flag('to', process.env.END_BLOCK ?? String(PRE_2024_END_BLOCK)));
  const fromBlock = Number(flag('from', '0'));
  const minLockedUsd = Number(flag('min-usd', process.env.MIN_LOCKED_USD ?? '100'));

  mkdirSync(DATA_DIR, { recursive: true });

  const mc = new MulticallEngine(rpcUrls(), {
    concurrency: Number(process.env.RPC_CONCURRENCY ?? 24),
    batchSize: Number(process.env.MULTICALL_BATCH_SIZE ?? 400),
  });

  const runId = await startRun({ fromBlock, toBlock: endBlock, thresholdUsd: minLockedUsd });

  try {
    // ---- Stage 1: discovery -------------------------------------------
    if (!has('skip-discovery') || !existsSync(POOLS_FILE)) {
      await discover({
        fromBlock,
        toBlock: endBlock,
        outPath: POOLS_FILE,
        onProgress: ({ block, total }) => {
          const pct = ((block - fromBlock) / (endBlock - fromBlock)) * 100;
          if (total % 50_000 < 500) {
            logger.info(`  discovery ${pct.toFixed(1)}% — block ${block.toLocaleString()}, ${total.toLocaleString()} pools`);
          }
        },
      });
    } else {
      logger.info('discovery: skipped (--skip-discovery), reusing data/pools.ndjson');
    }

    const pools = await readPools(POOLS_FILE);
    logger.info(`loaded ${pools.length.toLocaleString()} discovered pools`);

    // V3 valuation needs tick-range math to value a position; V2 is the bulk of
    // pre-2024 launches and is handled exactly. V3 is scoped as follow-up work
    // rather than approximated badly here.
    const v2 = pools.filter((p) => p.kind === 'v2');
    const v3 = pools.filter((p) => p.kind === 'v3');
    logger.info(`  ${v2.length.toLocaleString()} V2-style, ${v3.length.toLocaleString()} V3-style`);

    // ---- Stage 2: valuation -------------------------------------------
    const ethPriceUsd = await getEthPriceUsd(mc);
    logger.info(`ETH/USD from Chainlink: $${ethPriceUsd.toFixed(2)}`);

    const valued = await valueV2Pools(mc, v2, {
      ethPriceUsd,
      // Pre-filter on TOTAL value. A pool can't have $100 locked if it holds
      // less than $100 in the first place, so this is a safe, lossless narrow.
      minTotalUsd: minLockedUsd,
      onProgress: (done, total) => {
        if (done % 25_000 < 400) logger.info(`  valuation ${done.toLocaleString()}/${total.toLocaleString()}`);
      },
    });

    // ---- Stage 3: lock analysis ---------------------------------------
    const balances = await reconstructLpHolders(valued, {
      toBlock: endBlock,
      onProgress: (done, total) => logger.info(`  lp replay ${done.toLocaleString()}/${total.toLocaleString()}`),
    });

    const results = await analyzeLocks(mc, valued, balances, { minLockedUsd });

    // ---- Persist -------------------------------------------------------
    await persist(results, runId);
    await finishRun(runId, {
      poolsDiscovered: pools.length,
      poolsPriced: valued.length,
      poolsPassing: results.length,
      ethPriceUsd,
      timings: { totalMs: Date.now() - t0 },
    });

    const mins = ((Date.now() - t0) / 60000).toFixed(1);
    logger.info('');
    logger.info(`DONE in ${mins} min`);
    logger.info(`  discovered : ${pools.length.toLocaleString()}`);
    logger.info(`  priced     : ${valued.length.toLocaleString()}`);
    logger.info(`  passing    : ${results.length.toLocaleString()}  (>= $${minLockedUsd} locked)`);
  } catch (err) {
    await failRun(runId, (err as Error).message);
    throw err;
  }
}

/**
 * The locker registry in constants.ts is recalled from memory and explicitly
 * marked unverified. This command checks each entry actually has bytecode
 * before you rely on it, so a wrong address surfaces as a loud failure here
 * rather than as a silently missing category in your results.
 */
async function verifyLockers() {
  const mc = new MulticallEngine(rpcUrls());
  const sizes = await mc.getCodeSizes(LOCKERS.map((l) => l.address));
  logger.info('Locker registry check:');
  for (const l of LOCKERS) {
    const size = sizes.get(l.address.toLowerCase()) ?? -1;
    const verdict = size > 0 ? `OK (${size} bytes)` : size === 0 ? 'NO CODE — address is wrong or an EOA' : 'RPC error';
    logger.info(`  ${size > 0 ? 'PASS' : 'FAIL'}  ${l.name.padEnd(24)} ${l.address}  ${verdict}`);
  }
  logger.info('');
  logger.info('Entries that FAIL should be corrected or removed. Structural detection');
  logger.info('(contract-vs-EOA) still catches these pools regardless — the registry');
  logger.info('only improves labelling, never coverage.');
}

const main = { scan, 'verify-lockers': verifyLockers }[cmd];
if (!main) {
  console.error(`Unknown command "${cmd}". Try: scan | verify-lockers`);
  process.exit(1);
}
// Force a clean exit. The HyperSync client and postgres pool keep open handles
// that otherwise keep the process alive for minutes after work is done.
main()
  .then(() => process.exit(0))
  .catch((e) => {
    logger.error(e.stack ?? String(e));
    process.exit(1);
  });
