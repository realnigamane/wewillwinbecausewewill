/**
 * Per-contract risk FINDINGS — the bug-bounty detail layer.
 *
 * risk.ts answers "does this capability exist" as a flat flag. This module turns
 * each detected issue into a full, contract-SPECIFIC finding: what it is, the
 * exact attack path on THIS token (bounty framing), and what it means for whether
 * the token is safe to hold (assessment framing). Every string is generated from
 * the contract's own extracted facts — the owner address, the exact selector, the
 * specific pool and dollars at risk — so the same class on two different tokens
 * produces two different writeups.
 *
 * Everything here is static and derived from bytecode we already read. No
 * simulation, nothing broadcast on-chain.
 *
 * Honesty model: findings that rest on facts we detect reliably (a selector is
 * present; owner() returned a live address; the bytecode contains a DELEGATECALL
 * opcode) are `confidence: 'firm'`. Findings that rest on the heuristic guard
 * analysis (did a caller-check precede the state write?) are `confidence:
 * 'heuristic'` and say so, because bytecode access-control analysis without
 * source is approximate. We never present a heuristic as a certainty.
 */

export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type Confidence = 'firm' | 'heuristic';

export interface Finding {
  /** stable id: class + selector, so the UI can key/dedupe */
  id: string;
  class: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  /** the concrete facts this finding was built from — shown as evidence */
  evidence: Record<string, string | number | boolean | null>;
  /** bounty framing: the exact path to exploit THIS contract */
  attackPath: string;
  /** assessment framing: what it means for holding THIS token */
  assessment: string;
}

/** Everything the generators need about the specific contract under review. */
export interface FindingContext {
  token: string;
  symbol: string | null;
  quoteSymbol: string | null;
  pool: string;
  lockedUsd: number | null;
  ownerAddress: string | null;
  /** true = live owner, false = renounced/dead, null = unknown/not present */
  ownerActive: boolean | null;
  /** guard analysis verdict per class flag: true=guarded, false=unguarded, null=unknown */
  guard?: Record<string, boolean | null>;
}

const money = (n: number | null | undefined) =>
  n == null ? 'its liquidity pool' : `the ~$${Math.round(n).toLocaleString()} pool`;
const sym = (s: string | null) => s || 'this token';
const ownerDesc = (ctx: FindingContext) =>
  ctx.ownerActive === false
    ? 'a dead/zero address (ownership renounced)'
    : ctx.ownerAddress
      ? ctx.ownerAddress
      : 'the privileged account';

/**
 * Human function signature for a detected class, chosen for the writeup.
 * (The scanner matches several selector variants per class; we name the canonical
 * one so the prose reads concretely.)
 */
const CLASS_FN: Record<string, { sig: string; sel: string; verb: string }> = {
  MINT: { sig: 'mint(address,uint256)', sel: '0x40c10f19', verb: 'mint new tokens' },
  SET_BALANCE: { sig: 'setBalance(address,uint256)', sel: '0xe30443bc', verb: 'overwrite any wallet balance' },
  BLACKLIST: { sig: 'blacklist(address)', sel: '0xf9f92be4', verb: 'freeze a holder' },
  FEE_CTRL: { sig: 'setFee(uint256)', sel: '0x69fe0e2d', verb: 'change the buy/sell tax' },
  TRADING_TOGGLE: { sig: 'setTradingEnabled(bool)', sel: '0xc2e5ec04', verb: 'switch trading off' },
  PAUSABLE: { sig: 'pause()', sel: '0x8456cb59', verb: 'pause all transfers' },
  MAXTX: { sig: 'setMaxTxAmount(uint256)', sel: '0xec28438a', verb: 'shrink the max transaction size' },
};

function guardOf(ctx: FindingContext, cls: string): boolean | null {
  return ctx.guard?.[cls] ?? null;
}

/** Build the finding for one owner-gated capability class. */
function capabilityFinding(ctx: FindingContext, cls: string): Finding | null {
  const fn = CLASS_FN[cls];
  if (!fn) return null;
  const guard = guardOf(ctx, cls);
  const unguarded = guard === false;
  const S = sym(ctx.symbol);

  // --- class-specific consequence, written for THIS pool ---
  const consequences: Record<string, { attack: string; assess: string; sev: Severity }> = {
    MINT: {
      attack: `mint an unlimited amount of ${S} to a wallet it controls, then dump that fresh supply into ${money(ctx.lockedUsd)} at ${ctx.pool} — draining the ${ctx.quoteSymbol ?? 'paired'} side into the attacker's wallet in a single transaction`,
      assess: `every ${S} you hold can be diluted to near-zero at will; the circulating supply is not fixed`,
      sev: 'high',
    },
    SET_BALANCE: {
      attack: `write an arbitrary ${S} balance to any address (including zeroing yours and maxing its own), then sell into ${money(ctx.lockedUsd)} at ${ctx.pool}`,
      assess: `balances are not real — the contract can rewrite who owns what, so your holdings can be erased outright`,
      sev: 'critical',
    },
    BLACKLIST: {
      attack: `blacklist buyers right after they ape in, so they can never sell, while the controller keeps selling into ${money(ctx.lockedUsd)}`,
      assess: `you can be individually frozen out of selling ${S} at any moment — a classic honeypot lever`,
      sev: 'high',
    },
    FEE_CTRL: {
      attack: `raise the sell tax to ~100% the instant real buy volume appears, so every sell of ${S} is siphoned to the controller while the ${money(ctx.lockedUsd)} still shows as "liquidity"`,
      assess: `the tax you'll actually pay to sell is not what it is now — it can be turned into a wall that traps your exit`,
      sev: 'high',
    },
    TRADING_TOGGLE: {
      attack: `flip trading off for everyone except itself, sell its bag into ${money(ctx.lockedUsd)}, then leave sells disabled`,
      assess: `your ability to sell ${S} is a switch the controller holds — it can be turned off after you buy`,
      sev: 'high',
    },
    PAUSABLE: {
      attack: `pause all ${S} transfers to lock holders in place while positioning an exit`,
      assess: `transfers of ${S} can be frozen at the controller's discretion, stranding your position`,
      sev: 'medium',
    },
    MAXTX: {
      attack: `shrink the max transaction size to dust so nobody can sell a meaningful amount of ${S} at once`,
      assess: `sell size can be throttled to the point of being unusable — a softer honeypot`,
      sev: 'medium',
    },
  };

  const c = consequences[cls];
  if (!c) return null;

  if (unguarded) {
    // Heuristic said no caller check precedes the write -> anyone-can-call bug.
    return {
      id: `${cls}_UNGUARDED_${fn.sel}`,
      class: `${cls}_UNGUARDED`,
      title: `${fn.sig} appears callable by anyone`,
      severity: 'critical',
      confidence: 'heuristic',
      evidence: {
        selector: fn.sel,
        function: fn.sig,
        guardFound: false,
        token: ctx.token,
        pool: ctx.pool,
        lockedUsd: ctx.lockedUsd,
      },
      attackPath: `${fn.sig} (selector ${fn.sel}) writes to state, and the bytecode analysis found NO caller/owner check before that write. If that holds, any address — not just the dev — can call it: an attacker directly calls it to ${c.attack}. This is a directly exploitable bug, not merely a centralization risk. (Heuristic: confirm by decompiling the ${fn.sig} branch before acting.)`,
      assessment: `Critical, and it does not depend on trusting the deployer — ${'`'}${fn.sig}${'`'} looks reachable by anyone on-chain. If confirmed, ${S} is unsafe to hold or buy until the function is shown to be guarded. Verify against the decompiled source.`,
    };
  }

  // Owner-gated capability. Severity is amplified when the owner is still live.
  const live = ctx.ownerActive !== false;
  const sev: Severity = live ? c.sev : downgrade(c.sev);
  return {
    id: `${cls}_${fn.sel}`,
    class: cls,
    title: `Owner can ${fn.verb}${live ? '' : ' (ownership renounced)'}`,
    severity: sev,
    confidence: 'firm',
    evidence: {
      selector: fn.sel,
      function: fn.sig,
      owner: ctx.ownerAddress,
      ownerRenounced: ctx.ownerActive === false,
      guardFound: guard === true ? true : null,
      pool: ctx.pool,
      lockedUsd: ctx.lockedUsd,
    },
    attackPath:
      `The token exposes ${'`'}${fn.sig}${'`'} (selector ${fn.sel}), gated to ${ownerDesc(ctx)}. ` +
      (live
        ? `Because ownership is NOT renounced, that account can at any time ${c.attack}. No timelock or cap sits between the call and the effect, so it can execute in one block.`
        : `Ownership is renounced (owner is a dead/zero address), so the on-chain path to ${c.attack.split(',')[0]} is not currently callable via owner() — UNLESS a proxy or a second admin role can still reach it (check the other findings).`),
    assessment: live
      ? `Centralization risk: ${c.assess}. This is "trust the dev" territory — safe only for as long as ${ownerDesc(ctx)} chooses not to act. Renouncement or a timelock would neutralize it.`
      : `Lower risk here: the capability exists in the code but ownership is renounced, so ${c.assess.replace('can', 'could only')} if a separate admin path or upgradeable proxy re-enables it.`,
  };
}

function downgrade(s: Severity): Severity {
  return s === 'critical' ? 'high' : s === 'high' ? 'medium' : s === 'medium' ? 'low' : 'low';
}

/** Proxy finding — independent of owner state (an upgrade can bypass renouncement). */
function proxyFinding(ctx: FindingContext): Finding {
  const S = sym(ctx.symbol);
  return {
    id: 'PROXY_delegatecall',
    class: 'PROXY',
    title: 'Upgradeable — logic can be swapped',
    severity: 'critical',
    confidence: 'firm',
    evidence: { signal: 'DELEGATECALL opcode present', token: ctx.token, pool: ctx.pool, lockedUsd: ctx.lockedUsd },
    attackPath: `${S}'s bytecode routes through DELEGATECALL, so the code that runs is stored behind an implementation pointer the admin controls. The admin upgrades the implementation to a new one that adds a mint/blacklist/drain function, then uses it to sweep ${money(ctx.lockedUsd)} at ${ctx.pool}. Crucially this works even if ${'`'}owner()${'`'} looks renounced on the current implementation — renouncement of the proxy admin is a separate thing that must be checked independently.`,
    assessment: `Whatever ${S} does today is not a guarantee of what it will do tomorrow — the logic is replaceable. Any "this token is safe" read is only valid for the current implementation. Treat an upgradeable token's safety as provisional and check who controls the proxy admin / whether upgradeability is timelocked.`,
  };
}

function selfdestructFinding(ctx: FindingContext): Finding {
  const S = sym(ctx.symbol);
  return {
    id: 'SELFDESTRUCT',
    class: 'SELFDESTRUCT',
    title: 'Contract can self-destruct',
    severity: 'high',
    confidence: 'firm',
    evidence: { signal: 'SELFDESTRUCT opcode present', token: ctx.token },
    attackPath: `${S} contains a SELFDESTRUCT path. The controller destroys the token contract, after which every ${S} balance points at empty code — the token is bricked while any ${ctx.quoteSymbol ?? 'paired'} value already extracted from ${ctx.pool} stays with the attacker.`,
    assessment: `The token can be deleted out from under holders, permanently. Even burned/locked liquidity doesn't protect you if the token side itself ceases to exist.`,
  };
}

function ownerContextFinding(ctx: FindingContext): Finding | null {
  if (ctx.ownerActive !== true) return null;
  return {
    id: 'OWNER_ACTIVE',
    class: 'OWNER_ACTIVE',
    title: 'Ownership not renounced',
    severity: 'medium',
    confidence: 'firm',
    evidence: { owner: ctx.ownerAddress },
    attackPath: `Ownership is live at ${ctx.ownerAddress}. On its own this executes nothing — but it is the key that unlocks every owner-gated finding above. Whoever holds this key can trigger those paths at will.`,
    assessment: `This is the amplifier: it turns every "owner can…" capability from theoretical into currently-callable. If this address is a fresh EOA (not a multisig or timelock), treat the owner-gated findings as live threats rather than dormant ones.`,
  };
}

const OWNER_GATED = ['SET_BALANCE', 'MINT', 'BLACKLIST', 'TRADING_TOGGLE', 'FEE_CTRL', 'PAUSABLE', 'MAXTX'];

/**
 * Turn a set of detected class flags + context into ordered findings.
 * `flags` is the output of risk.ts scanSelectors plus PROXY/SELFDESTRUCT.
 */
export function generateFindings(ctx: FindingContext, flags: string[]): Finding[] {
  const set = new Set(flags);
  const out: Finding[] = [];

  for (const cls of OWNER_GATED) {
    if (set.has(cls)) {
      const f = capabilityFinding(ctx, cls);
      if (f) out.push(f);
    }
  }
  if (set.has('PROXY')) out.push(proxyFinding(ctx));
  if (set.has('SELFDESTRUCT')) out.push(selfdestructFinding(ctx));
  const oc = ownerContextFinding(ctx);
  if (oc) out.push(oc);

  const rank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  out.sort((a, b) => rank[a.severity] - rank[b.severity]);
  return out;
}
