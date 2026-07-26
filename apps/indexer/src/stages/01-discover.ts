/**
 * STAGE 1 — Discovery.
 *
 * Pull every Uniswap-V2-style and V3-style pool creation event on Ethereum
 * before 2024, from block 0.
 *
 * The important design decision: we filter by topic0 ONLY and pass no address
 * filter. HyperSync indexes by topic natively, so an address-less topic scan
 * costs the same as a filtered one — but it catches every fork of Uniswap ever
 * deployed (Sushi, Shiba, Pancake-on-ETH, Fraxswap, and the long tail of
 * hundreds of one-off forks) without us needing to know they exist. The
 * factory address falls out as the log's emitter.
 *
 * Expected output: ~1M+ pool creations, in single-digit minutes.
 */
import { HypersyncClient, type LogField } from '@envio-dev/hypersync-client';
import {
  TOPIC_PAIR_CREATED,
  TOPIC_POOL_CREATED,
  TOPIC_TO_KIND,
  PRE_2024_END_BLOCK,
} from '@liqarch/shared';
import { createWriteStream } from 'node:fs';
import { logger } from '../lib/log.js';
import type { DiscoveredPool } from '../lib/types.js';

/** Last 20 bytes of a 32-byte word, as a lowercase 0x address. */
function addrFromWord(word: string): string {
  return ('0x' + word.slice(-40)).toLowerCase();
}

/** Read the Nth 32-byte word out of a hex data blob. */
function word(data: string, n: number): string {
  const start = 2 + n * 64;
  return data.slice(start, start + 64);
}

export interface DiscoverOptions {
  fromBlock?: number;
  /** EXCLUSIVE, per HyperSync semantics. */
  toBlock?: number;
  /** NDJSON sink. Streaming to disk keeps peak memory flat regardless of result size. */
  outPath: string;
  onProgress?: (p: { block: number; total: number; elapsedMs: number }) => void;
}

export async function discover(opts: DiscoverOptions): Promise<{ total: number; factories: Map<string, number> }> {
  const fromBlock = opts.fromBlock ?? 0;
  const toBlock = opts.toBlock ?? PRE_2024_END_BLOCK;

  const apiToken = process.env.ENVIO_API_TOKEN;
  if (!apiToken) {
    throw new Error(
      'ENVIO_API_TOKEN is required. HyperSync made API tokens mandatory in Nov 2025.\n' +
        'Get a free one at https://envio.dev/app/api-tokens and put it in .env',
    );
  }

  const client = HypersyncClient.new({
    url: process.env.HYPERSYNC_URL ?? 'https://eth.hypersync.xyz',
    bearerToken: apiToken,
  });

  const query = {
    fromBlock,
    toBlock,
    logs: [
      // No `address` key => every factory, including undiscovered forks.
      { topics: [[TOPIC_PAIR_CREATED, TOPIC_POOL_CREATED]] },
    ],
    fieldSelection: {
      log: [
        'BlockNumber',
        'LogIndex',
        'TransactionHash',
        'Address',
        'Topic0',
        'Topic1',
        'Topic2',
        'Topic3',
        'Data',
      ] as LogField[],
      block: ['Number', 'Timestamp'] as const,
    },
  };

  const out = createWriteStream(opts.outPath, { encoding: 'utf8' });
  const factories = new Map<string, number>();
  const blockTimes = new Map<number, number>();
  const started = Date.now();
  let total = 0;
  let rawLogs = 0;

  logger.info(`discovery: blocks ${fromBlock} -> ${toBlock} (exclusive)`);

  const stream = await client.stream(query as any, {});

  try {
    for (;;) {
      const res = await stream.recv();
      if (res === null) break; // end of stream

      for (const b of res.data?.blocks ?? []) {
        if (b.number != null && b.timestamp != null) {
          blockTimes.set(Number(b.number), Number(b.timestamp));
        }
      }

      rawLogs += res.data?.logs?.length ?? 0;
      for (const log of res.data?.logs ?? []) {
        // The Node client returns indexed topics as ONE `topics` array —
        // NOT as log.topic0/topic1/... Reading the latter yields undefined and
        // silently drops every event (this is exactly what returned 0 pools).
        const topics = (log.topics ?? []) as (string | null | undefined)[];
        const topic0 = (topics[0] ?? '').toLowerCase();
        const kind = TOPIC_TO_KIND[topic0];
        if (!kind) continue;

        const data = log.data ?? '0x';
        // V2: data = [pair, allPairsLength]        -> pool is word 0
        // V3: data = [tickSpacing, pool]           -> pool is word 1
        const poolWord = kind === 'v2' ? word(data, 0) : word(data, 1);
        if (poolWord.length < 64) continue; // malformed / truncated, skip rather than emit garbage

        const blockNumber = Number(log.blockNumber);
        const rec: DiscoveredPool = {
          address: addrFromWord(poolWord),
          kind,
          factory: (log.address ?? '').toLowerCase(),
          token0: addrFromWord(topics[1] ?? ''),
          token1: addrFromWord(topics[2] ?? ''),
          feeTier: kind === 'v3' && topics[3] ? parseInt(topics[3] as string, 16) : null,
          createdBlock: blockNumber,
          createdTs: blockTimes.get(blockNumber) ?? null,
          createdTx: log.transactionHash ?? null,
        };

        out.write(JSON.stringify(rec) + '\n');
        factories.set(rec.factory, (factories.get(rec.factory) ?? 0) + 1);
        total++;
      }

      // Pagination. Critical: advance on nextBlock and terminate on reaching
      // toBlock — NOT on an empty batch. HyperSync's ~5s per-request execution
      // budget means empty batches are completely routine over sparse ranges,
      // and stopping on one would silently truncate the scan.
      const next = res.nextBlock;
      if (next != null) {
        (query as any).fromBlock = next;
        opts.onProgress?.({ block: Number(next), total, elapsedMs: Date.now() - started });
        if (Number(next) >= toBlock) break;
      }
    }
  } finally {
    await stream.close?.();
    await new Promise<void>((r) => out.end(r));
  }

  logger.info(
    `discovery: ${total.toLocaleString()} pools from ${factories.size} distinct factories ` +
      `(${rawLogs.toLocaleString()} raw creation logs seen) in ${((Date.now() - started) / 1000).toFixed(1)}s`,
  );

  return { total, factories };
}
