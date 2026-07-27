/**
 * STAGE 2 — Valuation (the cheap filter).
 *
 * Ordering matters enormously here. Lock analysis is expensive per pool; pool
 * valuation is cheap. So we value EVERY pool first, discard the ~90% that hold
 * less than the threshold in total, and only then run lock analysis on the
 * survivors. Doing it the other way round would multiply the scan time by
 * roughly an order of magnitude for identical output.
 *
 * Pricing needs no external price API. A pool is only priceable if one side is
 * a known quote asset (WETH/USDC/USDT/DAI/FRAX), in which case:
 *
 *     poolValueUsd = 2 x (quoteSideReserve in USD)
 *
 * ...because a constant-product pool holds equal value on both sides by
 * construction. ETH itself comes from the Chainlink ETH/USD feed read on-chain,
 * so the whole pipeline needs exactly zero API keys beyond the RPC.
 *
 * Pools with no quote-asset side (e.g. SHIB/PEPE) are marked unpriceable rather
 * than guessed at. Guessing would mean recursively deriving prices through the
 * pool graph, which is a legitimate feature but also a reliable way to produce
 * confident nonsense from a single manipulated pool. It is left as a follow-up.
 */
import { formatUnits } from 'viem';
import {
  QUOTE_ASSETS,
  UNIV2_PAIR_ABI,
  CHAINLINK_FEED_ABI,
  CHAINLINK_ETH_USD,
  MULTICALL3,
} from '@liqarch/shared';
import type { MulticallEngine, Call } from '../lib/multicall.js';
import type { DiscoveredPool, ValuedPool } from '../lib/types.js';
import { logger } from '../lib/log.js';

export async function getEthPriceUsd(mc: MulticallEngine): Promise<number> {
  const [round, dec] = await mc.execute([
    { target: CHAINLINK_ETH_USD, abi: CHAINLINK_FEED_ABI, functionName: 'latestRoundData' },
    { target: CHAINLINK_ETH_USD, abi: CHAINLINK_FEED_ABI, functionName: 'decimals' },
  ]);

  if (!round.success || !dec.success) {
    throw new Error('Could not read Chainlink ETH/USD feed — check your RPC endpoint');
  }

  const answer = (round.value as unknown[])[1] as bigint;
  const decimals = Number(dec.value as number);
  const price = Number(formatUnits(answer, decimals));

  // Sanity bound. If the feed ever returns something absurd we want a loud
  // failure, not a scan that silently values every pool at zero.
  if (!Number.isFinite(price) || price <= 0 || price > 1_000_000) {
    throw new Error(`Implausible ETH price from Chainlink: ${price}`);
  }
  return price;
}

/** Which side (0 or 1) is a priceable quote asset? null if neither. */
export function quoteSideOf(pool: DiscoveredPool): 0 | 1 | null {
  if (QUOTE_ASSETS[pool.token0]) return 0;
  if (QUOTE_ASSETS[pool.token1]) return 1;
  return null;
}

export interface ValueOptions {
  ethPriceUsd: number;
  /** Pools below this total value skip lock analysis entirely. */
  minTotalUsd: number;
  onProgress?: (done: number, total: number) => void;
}

/**
 * Value a batch of V2 pools. Three calls per pool: getReserves, totalSupply,
 * and token0 (to confirm ordering, since a handful of forks emit the event
 * with tokens in an order that doesn't match on-chain state).
 */
export async function valueV2Pools(
  mc: MulticallEngine,
  pools: DiscoveredPool[],
  opts: ValueOptions,
): Promise<ValuedPool[]> {
  const priceable = pools.filter((p) => quoteSideOf(p) !== null);
  logger.info(
    `valuation: ${priceable.length.toLocaleString()} / ${pools.length.toLocaleString()} pools have a quote-asset side`,
  );

  const calls: Call[] = [];
  for (const p of priceable) {
    calls.push({ target: p.address, abi: UNIV2_PAIR_ABI, functionName: 'getReserves' });
    calls.push({ target: p.address, abi: UNIV2_PAIR_ABI, functionName: 'totalSupply' });
    calls.push({ target: p.address, abi: UNIV2_PAIR_ABI, functionName: 'token0' });
  }

  const results = await mc.execute(calls, {
    onProgress: (done) => opts.onProgress?.(Math.floor(done / 3), priceable.length),
  });

  const out: ValuedPool[] = [];

  for (let i = 0; i < priceable.length; i++) {
    const p = priceable[i];
    const reservesRes = results[i * 3];
    const supplyRes = results[i * 3 + 1];
    const token0Res = results[i * 3 + 2];

    // A pool that can't answer getReserves is dead (self-destructed, or never
    // a real pair). Not an error — just not a result.
    if (!reservesRes.success || !supplyRes.success) continue;

    const reserves = reservesRes.value as unknown[];
    const reserve0 = reserves[0] as bigint;
    const reserve1 = reserves[1] as bigint;
    const lpTotalSupply = supplyRes.value as bigint;

    if (lpTotalSupply === 0n) continue; // no LP minted, nothing can be locked

    // Trust on-chain token0() over the event when they disagree.
    let side = quoteSideOf(p)!;
    if (token0Res.success) {
      const onChainToken0 = (token0Res.value as string).toLowerCase();
      if (onChainToken0 !== p.token0) {
        side = QUOTE_ASSETS[onChainToken0] ? 0 : 1;
      }
    }

    const quoteAddr = side === 0 ? p.token0 : p.token1;
    const quote = QUOTE_ASSETS[quoteAddr];
    if (!quote) continue;

    const quoteReserve = side === 0 ? reserve0 : reserve1;
    const quoteAmount = Number(formatUnits(quoteReserve, quote.decimals));
    const quoteUsd = quote.peg === 'eth' ? quoteAmount * opts.ethPriceUsd : quoteAmount;

    // Constant-product invariant: both sides hold equal value.
    const totalLiquidityUsd = quoteUsd * 2;

    if (totalLiquidityUsd < opts.minTotalUsd) continue;

    out.push({
      ...p,
      quoteSide: side,
      reserve0,
      reserve1,
      lpTotalSupply,
      totalLiquidityUsd,
    });
  }

  logger.info(
    `valuation: ${out.length.toLocaleString()} pools hold >= $${opts.minTotalUsd} total ` +
      `(${((out.length / Math.max(priceable.length, 1)) * 100).toFixed(1)}% survival)`,
  );

  return out;
}

const MC3_GETETHBALANCE_ABI = [
  {
    inputs: [{ name: 'addr', type: 'address' }],
    name: 'getEthBalance',
    outputs: [{ type: 'uint256' }],
    stateMutability: 'view',
    type: 'function',
  },
] as const;

const ERC20_MIN_ABI = [
  { inputs: [], name: 'totalSupply', outputs: [{ type: 'uint256' }], stateMutability: 'view', type: 'function' },
  {
    inputs: [{ name: 'a', type: 'address' }],
    name: 'balanceOf',
    outputs: [{ type: 'uint256' }],
    stateMutability: 'view',
    type: 'function',
  },
] as const;

/**
 * Value Uniswap V1 exchanges. Each exchange holds raw ETH + a token and IS its
 * own LP token, so we read: its ETH balance (via Multicall3.getEthBalance, which
 * batches inside the same aggregate), its LP totalSupply, and the token reserve.
 * Pool value = 2 x the ETH-side USD, exactly like a WETH-paired V2 pool.
 */
export async function valueV1Pools(
  mc: MulticallEngine,
  pools: DiscoveredPool[],
  opts: ValueOptions,
): Promise<ValuedPool[]> {
  if (pools.length === 0) return [];
  logger.info(`valuation(v1): ${pools.length.toLocaleString()} Uniswap V1 exchanges to price`);

  const calls: Call[] = [];
  for (const p of pools) {
    calls.push({ target: MULTICALL3, abi: MC3_GETETHBALANCE_ABI, functionName: 'getEthBalance', args: [p.address] });
    calls.push({ target: p.address, abi: ERC20_MIN_ABI, functionName: 'totalSupply' });
    calls.push({ target: p.token1, abi: ERC20_MIN_ABI, functionName: 'balanceOf', args: [p.address] });
  }

  const results = await mc.execute(calls, {
    onProgress: (done) => opts.onProgress?.(Math.floor(done / 3), pools.length),
  });

  const out: ValuedPool[] = [];
  for (let i = 0; i < pools.length; i++) {
    const p = pools[i];
    const ethRes = results[i * 3];
    const supRes = results[i * 3 + 1];
    const tokRes = results[i * 3 + 2];
    // A dead V1 exchange with no ETH balance can't be answered / holds nothing.
    if (!ethRes.success || !supRes.success) continue;

    const ethBalance = ethRes.value as bigint;
    const lpTotalSupply = supRes.value as bigint;
    if (lpTotalSupply === 0n) continue;

    const tokenBalance = tokRes.success ? (tokRes.value as bigint) : 0n;
    const ethAmount = Number(formatUnits(ethBalance, 18));
    const totalLiquidityUsd = ethAmount * opts.ethPriceUsd * 2;
    if (totalLiquidityUsd < opts.minTotalUsd) continue;

    out.push({
      ...p,
      quoteSide: 0, // WETH stands in for the ETH side
      reserve0: ethBalance,
      reserve1: tokenBalance,
      lpTotalSupply,
      totalLiquidityUsd,
    });
  }

  logger.info(
    `valuation(v1): ${out.length.toLocaleString()} exchanges hold >= $${opts.minTotalUsd} ` +
      `(${((out.length / Math.max(pools.length, 1)) * 100).toFixed(1)}% survival)`,
  );
  return out;
}
