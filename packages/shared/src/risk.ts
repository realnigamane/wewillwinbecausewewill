/**
 * Token-contract risk detection ("bug-bounty mode").
 *
 * This is DEFENSIVE classification, not exploitation. For each memecoin-side
 * token we read its on-chain runtime bytecode (one eth_getCode) and look for
 * the presence of dangerous owner-gated capabilities — the levers a dev uses to
 * rug or honeypot a token. We never call any of them; we only flag that they
 * exist so a researcher can judge (or avoid) the contract.
 *
 * Detection is two-pronged and needs zero API keys or verified source:
 *
 *   1. Function-selector scan. Every external function's 4-byte selector appears
 *      as a PUSH4 immediate in the dispatcher. We search the bytecode for the
 *      selectors of known-dangerous signatures. All selectors below were derived
 *      with a Keccak-256 implementation self-tested against canonical vectors
 *      (transfer=0xa9059cbb, mint=0x40c10f19, owner=0x8da5cb5b) — see
 *      scripts/verify-selectors.
 *
 *   2. Opcode scan (PUSH-aware). We walk the bytecode skipping PUSH data so we
 *      only match REAL opcodes, then flag DELEGATECALL (upgradeable proxy — the
 *      logic can be swapped out from under holders) and SELFDESTRUCT.
 *
 * Selector matching is a heuristic: a 4-byte constant could in theory collide
 * with a selector. In practice dispatcher PUSH4s make this rare, and the cost of
 * a false positive is "flagged for a human to look at", which is the right
 * failure direction for a risk tool.
 */
import { BURN_ADDRESSES } from './constants';

export type RiskSeverity = 'low' | 'med' | 'high' | 'crit';
export type RiskTier = 'clean' | 'low' | 'medium' | 'high' | 'critical';

export interface RiskCategory {
  flag: string;
  label: string;
  severity: RiskSeverity;
  weight: number;
  /** 4-byte selectors (no 0x, lowercase). Presence of ANY marks the flag. */
  selectors: string[];
}

/**
 * Owner-gated capability categories. Every one of these is only dangerous if
 * some admin can call it, so their weight is discounted when ownership is
 * provably renounced (see scoring below).
 */
export const RISK_CATEGORIES: RiskCategory[] = [
  {
    flag: 'SET_BALANCE',
    label: 'Arbitrary balance edits',
    severity: 'crit',
    weight: 40,
    selectors: ['e30443bc', 'e0b1cccb'], // setBalance(address,uint256), updateBalance(address,uint256)
  },
  {
    flag: 'MINT',
    label: 'Mintable supply',
    severity: 'high',
    weight: 22,
    selectors: ['40c10f19', 'a0712d68', '6a627842'], // mint(address,uint256) / mint(uint256) / mint(address)
  },
  {
    flag: 'BLACKLIST',
    label: 'Holder blacklist / freeze',
    severity: 'high',
    weight: 20,
    selectors: ['f9f92be4', '153b0d1e', '9cfe42da', '9c0db5f3', '342aa8b5'],
  },
  {
    flag: 'TRADING_TOGGLE',
    label: 'Trading on/off switch',
    severity: 'high',
    weight: 16,
    selectors: ['c2e5ec04', '8a8c523c', 'c9567bf9', 'e01af92c'],
  },
  {
    flag: 'FEE_CTRL',
    label: 'Adjustable fees / tax',
    severity: 'med',
    weight: 15,
    selectors: ['69fe0e2d', '0b78f9c0', 'e9dae5ed', 'dc1052e2', '8cd09d50', '061c82d0'],
  },
  {
    flag: 'PAUSABLE',
    label: 'Pausable transfers',
    severity: 'med',
    weight: 14,
    selectors: ['8456cb59', '3f4ba83a'], // pause() / unpause()
  },
  {
    flag: 'MAXTX',
    label: 'Max tx / wallet limits',
    severity: 'low',
    weight: 6,
    selectors: ['ec28438a', '5d0044ca'],
  },
];

/** owner() / getOwner() — used to resolve whether ownership is still live. */
export const OWNER_SELECTORS = { owner: '8da5cb5b', getOwner: '893d20e8' };

/** Non-category flags derived from opcodes / owner state, with display metadata. */
export const DERIVED_FLAGS: Record<string, { label: string; severity: RiskSeverity }> = {
  PROXY: { label: 'Upgradeable proxy (delegatecall)', severity: 'crit' },
  SELFDESTRUCT: { label: 'Self-destructible', severity: 'high' },
  OWNER_ACTIVE: { label: 'Owner not renounced', severity: 'med' },
  RENOUNCED: { label: 'Ownership renounced', severity: 'low' },
  NO_CODE: { label: 'No bytecode (dead / self-destructed)', severity: 'low' },
};

export const FLAG_LABEL: Record<string, string> = {
  ...Object.fromEntries(RISK_CATEGORIES.map((c) => [c.flag, c.label])),
  ...Object.fromEntries(Object.entries(DERIVED_FLAGS).map(([k, v]) => [k, v.label])),
};
export const FLAG_SEVERITY: Record<string, RiskSeverity> = {
  ...Object.fromEntries(RISK_CATEGORIES.map((c) => [c.flag, c.severity])),
  ...Object.fromEntries(Object.entries(DERIVED_FLAGS).map(([k, v]) => [k, v.severity])),
};

const DEAD = new Set<string>(BURN_ADDRESSES.map((a) => a.toLowerCase()));

export interface BytecodeAnalysis {
  hasCode: boolean;
  /** true = owner is a live address, false = renounced/dead, null = unknown. */
  ownerActive: boolean | null;
  /** The resolved owner() address (or null if not read), kept for finding detail. */
  ownerAddress: string | null;
  flags: string[];
  score: number; // 0..100
  tier: RiskTier;
}

function normHex(code: string): string {
  const h = (code || '').toLowerCase();
  return h.startsWith('0x') ? h.slice(2) : h;
}

/** Which risk categories' selectors appear in the bytecode. */
export function scanSelectors(code: string): string[] {
  const hex = normHex(code);
  const flags: string[] = [];
  for (const cat of RISK_CATEGORIES) {
    if (cat.selectors.some((s) => hex.includes(s))) flags.push(cat.flag);
  }
  return flags;
}

export function hasOwnerSelector(code: string): boolean {
  const hex = normHex(code);
  return hex.includes(OWNER_SELECTORS.owner) || hex.includes(OWNER_SELECTORS.getOwner);
}

/** Walk bytecode skipping PUSH data so only real opcodes are matched. */
export function scanOpcodes(code: string): { delegatecall: boolean; selfdestruct: boolean } {
  const hex = normHex(code);
  let delegatecall = false;
  let selfdestruct = false;
  for (let i = 0; i + 1 < hex.length; ) {
    const op = parseInt(hex.slice(i, i + 2), 16);
    if (Number.isNaN(op)) break;
    if (op >= 0x60 && op <= 0x7f) {
      // PUSH1..PUSH32 — skip the opcode byte plus its (op-0x5f) data bytes.
      i += 2 + (op - 0x5f) * 2;
      continue;
    }
    if (op === 0xf4) delegatecall = true;
    if (op === 0xff) selfdestruct = true;
    i += 2;
  }
  return { delegatecall, selfdestruct };
}

export function riskTierOf(score: number): RiskTier {
  if (score >= 55) return 'critical';
  if (score >= 32) return 'high';
  if (score >= 15) return 'medium';
  if (score >= 1) return 'low';
  return 'clean';
}

/**
 * @param code   runtime bytecode hex (0x…) from eth_getCode
 * @param owner  resolved owner() address, or null if not read / not present
 */
export function analyzeTokenBytecode(code: string, owner: string | null): BytecodeAnalysis {
  const hex = normHex(code);
  if (hex.length === 0) {
    return { hasCode: false, ownerActive: null, ownerAddress: owner, flags: ['NO_CODE'], score: 0, tier: 'clean' };
  }

  const ownerActive: boolean | null = owner == null ? null : !DEAD.has(owner.toLowerCase());
  const catFlags = scanSelectors(code);
  const { delegatecall, selfdestruct } = scanOpcodes(code);

  // Unknown ownership is treated as potentially-live (conservative).
  const owned = ownerActive !== false;

  let score = 0;
  const weightOf = new Map(RISK_CATEGORIES.map((c) => [c.flag, c.weight]));
  for (const f of catFlags) {
    const w = weightOf.get(f) ?? 0;
    score += owned ? w : w * 0.4;
  }
  // A proxy can swap logic regardless of the current owner state, so it isn't
  // discounted by renouncement.
  if (delegatecall) score += 30;
  if (selfdestruct) score += 20;
  if (ownerActive === true) score += 10;

  score = Math.min(100, Math.round(score));

  const flags = [...catFlags];
  if (delegatecall) flags.push('PROXY');
  if (selfdestruct) flags.push('SELFDESTRUCT');
  if (ownerActive === true) flags.push('OWNER_ACTIVE');
  else if (ownerActive === false) flags.push('RENOUNCED');

  return { hasCode: true, ownerActive, ownerAddress: owner, flags, score, tier: riskTierOf(score) };
}
