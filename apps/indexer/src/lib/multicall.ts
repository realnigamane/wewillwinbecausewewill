/**
 * Batched on-chain state reads.
 *
 * This is the throughput-critical path. Naively, checking ~1M pools needs
 * millions of eth_calls; at 50ms each that's weeks. Two things fix it:
 *
 *  1. Multicall3.aggregate3 packs hundreds of calls into ONE eth_call.
 *  2. We fire many multicalls concurrently against a rotating pool of RPC
 *     endpoints, with per-endpoint concurrency caps.
 *
 * Result: ~1M pools priced in minutes rather than weeks.
 *
 * `allowFailure: true` is mandatory. A large fraction of contracts in a 2017-2023
 * sweep are broken, self-destructed, or non-standard. One revert must never
 * poison a batch of 500 unrelated calls.
 */
import {
  createPublicClient,
  http,
  encodeFunctionData,
  decodeFunctionResult,
  type Abi,
  type PublicClient,
} from 'viem';
import { mainnet } from 'viem/chains';
import { MULTICALL3, MULTICALL3_ABI } from '@liqarch/shared';
import pLimit from 'p-limit';
import { logger } from './log.js';

export interface Call {
  target: string;
  abi: Abi | readonly unknown[];
  functionName: string;
  args?: readonly unknown[];
}

export interface CallResult<T = unknown> {
  success: boolean;
  value: T | null;
  error?: string;
}

export class MulticallEngine {
  private clients: PublicClient[];
  // Separate client pool for eth_getCode with JSON-RPC batching ON. getCode
  // can't ride Multicall3 (it's a node method, not a contract call), so without
  // batching it degenerates to one HTTP request per address — which is exactly
  // what free endpoints rate-limit into the ground (the ~20-min lock-analysis
  // wall). `batch` coalesces the concurrent getCode calls into a handful of
  // POSTs. Kept off the valuation clients so aggregate3 payloads never get
  // bundled into oversized requests that some nodes reject.
  private codeClients: PublicClient[];
  private cursor = 0;
  private codeCursor = 0;
  private limit: ReturnType<typeof pLimit>;
  private codeConcurrency: number;
  readonly batchSize: number;

  constructor(rpcUrls: string[], opts: { concurrency?: number; batchSize?: number } = {}) {
    if (rpcUrls.length === 0) throw new Error('At least one RPC URL is required (set RPC_URLS in .env)');

    this.clients = rpcUrls.map((url) =>
      createPublicClient({
        chain: mainnet,
        transport: http(url, {
          // viem retries transient failures for us; public endpoints flake constantly.
          retryCount: 3,
          retryDelay: 250,
          timeout: 30_000,
        }),
      }),
    );

    this.codeClients = rpcUrls.map((url) =>
      createPublicClient({
        chain: mainnet,
        transport: http(url, {
          retryCount: 3,
          retryDelay: 250,
          timeout: 30_000,
          // Coalesce up to 100 concurrent getCode requests into one POST,
          // waiting 20ms to let a batch fill.
          batch: { wait: 20, batchSize: 100 },
        }),
      }),
    );

    // Concurrency scales with endpoint count — each endpoint gets its own budget.
    this.limit = pLimit(opts.concurrency ?? rpcUrls.length * 8);
    // getCode is now batched, so we can keep a lot in flight regardless of how
    // few endpoints there are — the requests collapse into shared POSTs anyway.
    this.codeConcurrency = Math.max(200, rpcUrls.length * 32);
    this.batchSize = opts.batchSize ?? 400;
  }

  /** Round-robin so no single endpoint absorbs the whole scan and rate-limits us. */
  private next(): PublicClient {
    const c = this.clients[this.cursor % this.clients.length];
    this.cursor++;
    return c;
  }

  /**
   * Execute one aggregate3 batch. Returns results positionally aligned with
   * the input array — index i of the output always corresponds to calls[i],
   * successful or not.
   */
  private async runBatch(calls: Call[], blockNumber?: bigint): Promise<CallResult[]> {
    const encoded = calls.map((c) => ({
      target: c.target as `0x${string}`,
      allowFailure: true,
      callData: encodeFunctionData({
        abi: c.abi as Abi,
        functionName: c.functionName,
        args: c.args as never,
      }),
    }));

    const client = this.next();
    const raw = (await client.readContract({
      address: MULTICALL3 as `0x${string}`,
      abi: MULTICALL3_ABI as Abi,
      functionName: 'aggregate3',
      args: [encoded],
      ...(blockNumber ? { blockNumber } : {}),
    })) as { success: boolean; returnData: `0x${string}` }[];

    return raw.map((r, i) => {
      if (!r.success || r.returnData === '0x') {
        return { success: false, value: null, error: 'call reverted or returned empty' };
      }
      try {
        const value = decodeFunctionResult({
          abi: calls[i].abi as Abi,
          functionName: calls[i].functionName,
          data: r.returnData,
        });
        return { success: true, value };
      } catch (e) {
        // Decoded shape didn't match the ABI — e.g. a bytes32 symbol() on an
        // old token. Caller decides whether to retry with an alternate ABI.
        return { success: false, value: null, error: `decode failed: ${(e as Error).message}` };
      }
    });
  }

  /**
   * Chunk an arbitrarily large call list into batches and run them concurrently.
   * On batch failure we halve and retry, because the usual cause is a batch
   * that exceeded the node's gas or response-size limit rather than a bad call.
   */
  async execute(calls: Call[], opts: { blockNumber?: bigint; onProgress?: (done: number) => void } = {}): Promise<CallResult[]> {
    const chunks: { start: number; calls: Call[] }[] = [];
    for (let i = 0; i < calls.length; i += this.batchSize) {
      chunks.push({ start: i, calls: calls.slice(i, i + this.batchSize) });
    }

    const results = new Array<CallResult>(calls.length);
    let done = 0;

    await Promise.all(
      chunks.map((chunk) =>
        this.limit(async () => {
          const out = await this.runWithSplit(chunk.calls, opts.blockNumber);
          for (let i = 0; i < out.length; i++) results[chunk.start + i] = out[i];
          done += chunk.calls.length;
          opts.onProgress?.(done);
        }),
      ),
    );

    return results;
  }

  private async runWithSplit(calls: Call[], blockNumber?: bigint, depth = 0): Promise<CallResult[]> {
    try {
      return await this.runBatch(calls, blockNumber);
    } catch (e) {
      if (calls.length === 1 || depth > 6) {
        // Genuinely un-callable. Mark as failed rather than aborting the scan.
        return calls.map(() => ({ success: false, value: null, error: (e as Error).message }));
      }
      const mid = Math.floor(calls.length / 2);
      if (depth === 0) {
        logger.debug(`batch of ${calls.length} failed, splitting: ${(e as Error).message.slice(0, 120)}`);
      }
      const [a, b] = await Promise.all([
        this.runWithSplit(calls.slice(0, mid), blockNumber, depth + 1),
        this.runWithSplit(calls.slice(mid), blockNumber, depth + 1),
      ]);
      return [...a, ...b];
    }
  }

  /** Pin every read in a scan to one block so reserves and supplies stay mutually consistent. */
  async currentBlock(): Promise<bigint> {
    return this.next().getBlockNumber();
  }

  /**
   * Bytecode presence check, batched. This is the backbone of lock detection:
   * an LP balance sitting at an address WITH bytecode cannot be casually
   * withdrawn by a keyholder, whereas the same balance at an EOA can leave at
   * any moment. Distinguishing the two is the whole game.
   */
  async getCodeSizes(addresses: string[]): Promise<Map<string, number>> {
    const out = new Map<string, number>();
    const lim = pLimit(this.codeConcurrency);
    await Promise.all(
      addresses.map((addr) =>
        lim(async () => {
          const client = this.codeClients[this.codeCursor++ % this.codeClients.length];
          try {
            const code = await client.getCode({ address: addr as `0x${string}` });
            out.set(addr.toLowerCase(), code && code !== '0x' ? (code.length - 2) / 2 : 0);
          } catch {
            out.set(addr.toLowerCase(), -1); // unknown, distinct from "confirmed no code"
          }
        }),
      ),
    );
    return out;
  }

  /**
   * Full runtime bytecode per address, batched (JSON-RPC batching on). Risk
   * analysis scans this for dangerous function selectors. Returns '0x' for
   * addresses with no code, '' when the fetch itself failed.
   */
  async getCodes(addresses: string[]): Promise<Map<string, string>> {
    const out = new Map<string, string>();
    const lim = pLimit(this.codeConcurrency);
    await Promise.all(
      addresses.map((addr) =>
        lim(async () => {
          const client = this.codeClients[this.codeCursor++ % this.codeClients.length];
          try {
            const code = await client.getCode({ address: addr as `0x${string}` });
            out.set(addr.toLowerCase(), code ?? '0x');
          } catch {
            out.set(addr.toLowerCase(), '');
          }
        }),
      ),
    );
    return out;
  }
}
