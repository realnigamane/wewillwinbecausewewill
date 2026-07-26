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

import type { CodeVulns } from './disasm';

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
  /** disassembly-derived non-owner-exploit signals (guards, init, reentrancy…) */
  code?: CodeVulns;
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
  return ctx.code?.guard?.[cls] ?? null;
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
      attackPath: `WHAT: ${fn.sig} (selector ${fn.sel}) changes contract state, but the disassembly finds no msg.sender / owner check before that write — the access-control guard is missing. WHY IT WORKS: with nothing checking the caller, the EVM lets ANY address reach the state-changing code; ownership is never consulted, so "renounced" or not is irrelevant. HOW A RANDOM PERSON DOES IT: open ${S} on Etherscan → "Write Contract" (or "Write as Proxy") → connect any wallet → call ${fn.sig} directly to ${c.attack}. No dev key, one transaction, and it's repeatable. PREVENTION: add an access modifier (OpenZeppelin onlyOwner / AccessControl) so the function's first act is to require the caller is the owner/admin and revert otherwise.`,
      assessment: `Critical — and it does NOT depend on trusting the deployer. ${fn.sig} looks callable by anyone on-chain, so ${S} can be drained or bricked by a complete stranger. Do not hold or buy until you confirm it reverts for non-privileged callers. HOW TO VERIFY: on Etherscan's Write tab, try calling it from a throwaway wallet, or read the decompiled ${fn.sig} branch for a msg.sender check. (Heuristic — flagged from bytecode, confirm before acting.)`,
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

// --- non-owner-exploit findings (the bug-bounty class) ---------------------

function unprotectedInitFinding(ctx: FindingContext): Finding | null {
  const sig = ctx.code?.unprotectedInit;
  if (!sig) return null;
  const S = sym(ctx.symbol);
  return {
    id: 'UNPROTECTED_INIT',
    class: 'UNPROTECTED_INIT',
    title: `Anyone can call ${sig} and seize the contract`,
    severity: 'critical',
    confidence: 'heuristic',
    evidence: { function: sig, token: ctx.token },
    attackPath: `WHAT: ${sig} writes state (initializers usually set the owner/admin) with no caller check and no visible "already initialized" guard. WHY IT WORKS: an initializer is meant to run once at deploy behind an initializer modifier; without it the door stays open forever. HOW: anyone calls ${sig} from any wallet (Etherscan Write tab) to set THEMSELVES as owner of ${S}. Every owner-gated lever — mint, blacklist, drain, upgrade — is then theirs. On a proxy this is the textbook "uninitialized proxy" takeover. PREVENTION: use OpenZeppelin's initializer / reinitializer modifier (or require(!initialized) then set the flag) and set the owner in that same call.`,
    assessment: `Critical takeover: if ${sig} is truly open, ${S} has no stable owner — a stranger can claim admin and act as the owner. Treat as hostile until confirmed. VERIFY on Etherscan: is ${sig} exposed on the Write tab, and does calling it revert?`,
  };
}

function ownershipSeizeFinding(ctx: FindingContext): Finding | null {
  const sig = ctx.code?.unguardedOwnershipXfer;
  if (!sig) return null;
  const S = sym(ctx.symbol);
  return {
    id: 'UNGUARDED_OWNERSHIP',
    class: 'UNGUARDED_OWNERSHIP',
    title: `Anyone can call ${sig} to become owner`,
    severity: 'critical',
    confidence: 'heuristic',
    evidence: { function: sig, token: ctx.token, pool: ctx.pool },
    attackPath: `WHAT: ${sig} reassigns the owner, and the disassembly finds no msg.sender check before that write. WHY IT WORKS: transferOwnership is supposed to be onlyOwner; here the caller check is absent. HOW: a random person calls ${sig} with their OWN address — or has a contract they deployed call it — to become owner of ${S}. Once owner, they unlock every owner-gated function: mint to themselves, disable sells, and drain ${money(ctx.lockedUsd)} at ${ctx.pool}. PREVENTION: restore the onlyOwner guard on transferOwnership (OpenZeppelin Ownable does this by default).`,
    assessment: `Critical: ownership of ${S} appears grabbable by anyone — a takeover door for any stranger, not just a dev rug. Don't touch until confirmed. VERIFY: call ${sig} from a throwaway wallet on Etherscan and see whether it reverts.`,
  };
}

function txOriginFinding(ctx: FindingContext): Finding | null {
  const sig = ctx.code?.txOriginAuth;
  if (!sig) return null;
  const S = sym(ctx.symbol);
  return {
    id: 'TX_ORIGIN_AUTH',
    class: 'TX_ORIGIN_AUTH',
    title: `Owner check uses tx.origin — spoofable via a contract (${sig})`,
    severity: 'high',
    confidence: 'heuristic',
    evidence: { function: sig, token: ctx.token },
    attackPath: `WHAT: ${sig} touches tx.origin — a strong sign it authenticates with "tx.origin == owner" instead of "msg.sender == owner". WHY IT WORKS: tx.origin is the EOA that STARTED the transaction, not the immediate caller. So if the real owner can be lured into calling an attacker's contract, that contract can turn around and call ${S}, and the tx.origin check still sees the owner. HOW A RANDOM PERSON DOES IT: deploy a plausible contract (a fake airdrop claim, a "gift", a phishing dApp), get the owner to send it ONE transaction, and inside that call have your contract invoke ${sig} on ${S} as if it were the owner — mint to yourself, reassign owner, flip privileged switches. Your contract is the middleman that impersonates the owner. PREVENTION: never use tx.origin for authorization — use msg.sender == owner.`,
    assessment: `High: ${S}'s owner can be impersonated by a contract the owner merely interacts with — the "spoof the owner" class. It needs the owner to take one action on the attacker's contract (phishing), so it's not push-button, but it's a real path to full owner powers. VERIFY: read ${sig} for a tx.origin comparison used as an access check.`,
  };
}

function publicSelfdestructFinding(ctx: FindingContext): Finding | null {
  if (!ctx.code?.publicSelfdestruct) return null;
  const S = sym(ctx.symbol);
  return {
    id: 'PUBLIC_SELFDESTRUCT',
    class: 'PUBLIC_SELFDESTRUCT',
    title: `Anyone can trigger self-destruct`,
    severity: 'critical',
    confidence: 'heuristic',
    evidence: { token: ctx.token },
    attackPath: `WHAT: a function reaches the SELFDESTRUCT opcode along a path with no msg.sender check. WHY IT WORKS: SELFDESTRUCT deletes the contract; if the function isn't access-controlled, anyone can fire it. HOW: a random person (or their contract) calls that function to destroy ${S}'s contract — every holder's balance then points at empty code and ${S} is permanently bricked, while any ${ctx.quoteSymbol ?? 'paired'} value already pulled from ${ctx.pool} is gone. PREVENTION: remove SELFDESTRUCT (a token rarely needs it) or gate it behind strict access control + a timelock.`,
    assessment: `Critical griefing/rug: a stranger may be able to delete ${S} outright. Locked liquidity is no protection if the token contract itself can be destroyed. VERIFY which function reaches the self-destruct and whether it checks the caller.`,
  };
}

function reentrancyFinding(ctx: FindingContext): Finding | null {
  const fns = ctx.code?.reentrancy;
  if (!fns || !fns.length) return null;
  const S = sym(ctx.symbol);
  const list = fns.slice(0, 3).join(', ');
  return {
    id: 'REENTRANCY',
    class: 'REENTRANCY',
    title: `State changes after an external call — reentrancy surface (${list})`,
    severity: 'high',
    confidence: 'heuristic',
    evidence: { functions: fns.join(', '), token: ctx.token },
    attackPath: `WHAT: ${list} make an external CALL and then update ${S}'s storage AFTER the call returns (a checks-effects-interactions violation). WHY IT WORKS: the external call hands control to the callee before state is finalized, so a malicious contract can call back in ("re-enter") while balances/flags are stale. HOW A RANDOM PERSON DOES IT: deploy their OWN contract, arrange to be the call target (recipient/hook), and in the fallback re-enter ${S} — double-spending or corrupting accounting, potentially against ${money(ctx.lockedUsd)} at ${ctx.pool}. This is the "interact with it from your own contract" class you can't pull off from a plain wallet. PREVENTION: checks-effects-interactions (write all state BEFORE the external call) and/or a nonReentrant guard.`,
    assessment: `High: a normal buyer is fine, but an attacker with a custom contract may re-enter and break ${S}'s accounting. Reentrancy needs manual confirmation (the call target and any guard matter). VERIFY by reading the flagged function(s) for state writes placed after the external call.`,
  };
}

function upgradeFinding(ctx: FindingContext): Finding | null {
  const sig = ctx.code?.unguardedUpgrade;
  if (!sig) return null;
  const S = sym(ctx.symbol);
  return {
    id: 'UNGUARDED_UPGRADE',
    class: 'UNGUARDED_UPGRADE',
    title: `Anyone can call ${sig} and replace the contract's code`,
    severity: 'critical',
    confidence: 'heuristic',
    evidence: { function: sig, token: ctx.token, pool: ctx.pool },
    attackPath: `WHAT: ${sig} repoints this (proxy) token at a new implementation address, and the disassembly finds no msg.sender check before it. WHY IT WORKS: the upgrade path is meant to be admin-only; unguarded, anyone can repoint the proxy. The proxy keeps ${S}'s balances and storage but runs WHOEVER'S code the caller supplies. HOW A RANDOM PERSON DOES IT: deploy their OWN implementation contract — one whose functions mint them the whole supply, or a drain() that sends the pool to them — then call ${sig} with that address. ${S} now literally executes the attacker's logic over the real holders' balances, and they sweep ${money(ctx.lockedUsd)} at ${ctx.pool}. This is the most complete takeover there is. PREVENTION: gate the upgrade with onlyOwner / a ProxyAdmin behind a timelock (OpenZeppelin TransparentUpgradeableProxy, or UUPS with a real _authorizeUpgrade).`,
    assessment: `Critical — full takeover. If ${sig} is open, ${S}'s code can be swapped for a stranger's at will, so nothing about the token is trustworthy. Do not hold. VERIFY: does ${sig} appear on Etherscan's Write tab and revert for a non-admin caller?`,
  };
}

function arbitraryDelegatecallFinding(ctx: FindingContext): Finding | null {
  const sig = ctx.code?.arbitraryDelegatecall;
  if (!sig) return null;
  const S = sym(ctx.symbol);
  return {
    id: 'ARBITRARY_DELEGATECALL',
    class: 'ARBITRARY_DELEGATECALL',
    title: `A callable function delegatecalls with no caller check (${sig})`,
    severity: 'critical',
    confidence: 'heuristic',
    evidence: { function: sig, token: ctx.token, pool: ctx.pool },
    attackPath: `WHAT: ${sig} performs a DELEGATECALL and the disassembly finds no msg.sender check guarding it. WHY IT WORKS: delegatecall runs the target contract's code INSIDE ${S}'s own storage and with ${S}'s balances — as if that code were part of the token. If the target is caller-supplied and unguarded, the attacker chooses the code. HOW A RANDOM PERSON DOES IT: deploy a tiny contract whose function does exactly what they want — set themselves as owner, mint themselves the supply, approve themselves ${S}'s holdings, or self-destruct it — then call ${sig} pointing at that contract. ${S} delegatecalls into it and runs the attacker's code against the real token state, then they drain ${money(ctx.lockedUsd)} at ${ctx.pool}. This is the "deploy a contract and interact in an unintended way" class at its most severe. PREVENTION: never delegatecall a caller-supplied address; restrict delegatecall to a fixed, audited implementation and gate the entrypoint with onlyOwner.`,
    assessment: `Critical: a stranger's contract can execute as ${S} itself. Everything the token can touch is reachable. Treat as fully compromised until proven otherwise. VERIFY: read ${sig} — is the delegatecall target caller-controlled, and is there any access check?`,
  };
}

function burnFromFinding(ctx: FindingContext): Finding | null {
  const sig = ctx.code?.publicBurnFrom;
  if (!sig) return null;
  const S = sym(ctx.symbol);
  return {
    id: 'PUBLIC_BURN_FROM',
    class: 'PUBLIC_BURN_FROM',
    title: `Anyone may be able to burn others' ${S} via ${sig}`,
    severity: 'high',
    confidence: 'heuristic',
    evidence: { function: sig, token: ctx.token },
    attackPath: `WHAT: ${sig} reduces a target address's balance, and the disassembly finds no caller/allowance check before that write. WHY IT WORKS: burnFrom is supposed to require the caller be approved to spend that balance; without the check, "from" is just a parameter anyone can set. HOW A RANDOM PERSON DOES IT: call ${sig} with any victim's address to destroy their ${S} — grief a rival, or burn everyone but themselves to corner the supply, then sell into ${money(ctx.lockedUsd)} at ${ctx.pool}. PREVENTION: spend the caller's allowance first — _spendAllowance(from, msg.sender, amount) before _burn — exactly as OpenZeppelin's ERC20Burnable does.`,
    assessment: `High: ${S} balances may be destroyable by anyone, not just their holder — that breaks the token's most basic guarantee. VERIFY: read ${sig} for an allowance/caller check before it burns.`,
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

  // Self-destruct: anyone-can-trigger (critical) supersedes the owner-only framing.
  if (ctx.code?.publicSelfdestruct) {
    const psd = publicSelfdestructFinding(ctx);
    if (psd) out.push(psd);
  } else if (set.has('SELFDESTRUCT')) {
    out.push(selfdestructFinding(ctx));
  }

  // Non-owner-exploit findings (the bug-bounty class).
  const init = unprotectedInitFinding(ctx);
  if (init) out.push(init);
  const seize = ownershipSeizeFinding(ctx);
  if (seize) out.push(seize);
  const txo = txOriginFinding(ctx);
  if (txo) out.push(txo);
  const re = reentrancyFinding(ctx);
  if (re) out.push(re);
  const up = upgradeFinding(ctx);
  if (up) out.push(up);
  const adc = arbitraryDelegatecallFinding(ctx);
  if (adc) out.push(adc);
  const bfr = burnFromFinding(ctx);
  if (bfr) out.push(bfr);

  const oc = ownerContextFinding(ctx);
  if (oc) out.push(oc);

  const rank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  out.sort((a, b) => rank[a.severity] - rank[b.severity]);
  return out;
}
