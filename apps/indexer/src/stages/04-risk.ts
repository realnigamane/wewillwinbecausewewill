/**
 * STAGE 4 — Token risk / bug-bounty analysis.
 *
 * Runs on the memecoin (non-quote) side of each surviving pool. One eth_getCode
 * per distinct token (batched), plus one owner()/getOwner() read for tokens that
 * expose ownership, then pure classification (see @liqarch/shared risk.ts).
 *
 * Strictly read-only: we detect that a contract CAN mint / blacklist / retax /
 * halt trading / self-destruct / be upgraded — we never call any of it.
 */
import type { MulticallEngine, Call } from '../lib/multicall.js';
import {
  analyzeTokenBytecode,
  hasOwnerSelector,
  OWNER_SELECTORS,
  type BytecodeAnalysis,
} from '@liqarch/shared';
import { logger } from '../lib/log.js';

const OWNER_ABI = [
  { inputs: [], name: 'owner', outputs: [{ type: 'address' }], stateMutability: 'view', type: 'function' },
  { inputs: [], name: 'getOwner', outputs: [{ type: 'address' }], stateMutability: 'view', type: 'function' },
] as const;

/** Analyze a set of token addresses -> risk classification per (lowercased) token. */
export async function analyzeTokenRisk(
  mc: MulticallEngine,
  tokenAddrs: string[],
): Promise<Map<string, BytecodeAnalysis>> {
  const tokens = [...new Set(tokenAddrs.map((a) => a.toLowerCase()))];
  const out = new Map<string, BytecodeAnalysis>();
  if (tokens.length === 0) return out;

  const codes = await mc.getCodes(tokens);

  // Resolve owner() only for tokens that actually expose an ownership getter.
  const ownerTargets: string[] = [];
  const ownerFn = new Map<string, 'owner' | 'getOwner'>();
  for (const t of tokens) {
    const code = codes.get(t) ?? '';
    if (!code || code === '0x') continue;
    if (!hasOwnerSelector(code)) continue;
    const useOwner = code.toLowerCase().includes(OWNER_SELECTORS.owner);
    ownerFn.set(t, useOwner ? 'owner' : 'getOwner');
    ownerTargets.push(t);
  }

  const ownerOf = new Map<string, string | null>();
  if (ownerTargets.length) {
    const calls: Call[] = ownerTargets.map((t) => ({
      target: t,
      abi: OWNER_ABI,
      functionName: ownerFn.get(t)!,
    }));
    const res = await mc.execute(calls);
    ownerTargets.forEach((t, i) => {
      const r = res[i];
      ownerOf.set(t, r?.success ? (r.value as string).toLowerCase() : null);
    });
  }

  for (const t of tokens) {
    out.set(t, analyzeTokenBytecode(codes.get(t) ?? '', ownerOf.get(t) ?? null));
  }

  const flagged = [...out.values()].filter((a) => a.tier !== 'clean').length;
  logger.info(
    `risk: analyzed ${tokens.length.toLocaleString()} tokens, ${flagged.toLocaleString()} carry at least one flag`,
  );
  return out;
}
