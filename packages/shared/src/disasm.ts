/**
 * Minimal EVM disassembler + access-control analyzer.
 *
 * Purpose: find functions a NON-OWNER can exploit — the opposite of the
 * "owner can rug" centralization flags. From runtime bytecode alone (no source)
 * we approximate, per external function:
 *
 *   - does it write state (SSTORE)?
 *   - is there a msg.sender (CALLER) check BEFORE that write?  -> access control
 *   - does it make an external CALL, and does state change AFTER it? -> reentrancy
 *   - can it reach SELFDESTRUCT?
 *
 * A privileged/state-changing function with NO caller check before its write is
 * a candidate "anyone can call this" bug: a random person can invoke it straight
 * from Etherscan's Write tab, or from their own contract.
 *
 * HONESTY: this is a heuristic. Bytecode access-control analysis without source
 * has false positives (guards via mappings/modifiers we don't model) and false
 * negatives. Callers must label findings as heuristic and cite the function so a
 * human can confirm on Etherscan. It is a lead generator, not a verdict.
 */

// --- opcodes we care about -------------------------------------------------
const OP = {
  STOP: 0x00,
  ORIGIN: 0x32,
  CALLER: 0x33,
  CALLVALUE: 0x34,
  SLOAD: 0x54,
  SSTORE: 0x55,
  JUMP: 0x56,
  JUMPI: 0x57,
  JUMPDEST: 0x5b,
  EQ: 0x14,
  RETURN: 0xf3,
  CALL: 0xf1,
  CALLCODE: 0xf2,
  DELEGATECALL: 0xf4,
  STATICCALL: 0xfa,
  CREATE: 0xf0,
  CREATE2: 0xf5,
  REVERT: 0xfd,
  INVALID: 0xfe,
  SELFDESTRUCT: 0xff,
};

export interface Instr {
  pc: number;
  op: number;
  push?: string; // hex data for PUSH1..32 (no 0x)
}

function strip0x(h: string): string {
  const s = (h || '').toLowerCase();
  return s.startsWith('0x') ? s.slice(2) : s;
}

export function disassemble(codeHex: string): Instr[] {
  const hex = strip0x(codeHex);
  const out: Instr[] = [];
  for (let i = 0; i + 1 < hex.length; ) {
    const pc = i / 2;
    const op = parseInt(hex.slice(i, i + 2), 16);
    if (Number.isNaN(op)) break;
    if (op >= 0x60 && op <= 0x7f) {
      const n = op - 0x5f;
      out.push({ pc, op, push: hex.slice(i + 2, i + 2 + n * 2) });
      i += 2 + n * 2;
    } else {
      out.push({ pc, op });
      i += 2;
    }
  }
  return out;
}

/**
 * Parse the solidity function dispatcher: selector -> handler PC.
 * Matches the common shape PUSH4 <sel> ... EQ ... PUSH<n> <dest> JUMPI.
 */
export function buildDispatch(instrs: Instr[]): Map<string, number> {
  const m = new Map<string, number>();
  for (let i = 0; i < instrs.length; i++) {
    if (instrs[i].op === 0x63 && instrs[i].push && instrs[i].push!.length === 8) {
      // find EQ within a short window
      for (let j = i + 1; j < Math.min(i + 5, instrs.length); j++) {
        if (instrs[j].op === OP.EQ) {
          // then a PUSH dest followed by JUMPI
          for (let k = j; k < Math.min(j + 4, instrs.length - 1); k++) {
            if (instrs[k].op >= 0x60 && instrs[k].op <= 0x7f && instrs[k].push && instrs[k + 1].op === OP.JUMPI) {
              m.set('0x' + instrs[i].push, parseInt(instrs[k].push!, 16));
            }
          }
          break;
        }
      }
    }
  }
  return m;
}

export interface HandlerAnalysis {
  writesState: boolean;
  callerBeforeWrite: boolean;
  hasExternalCall: boolean;
  stateChangeAfterCall: boolean; // reentrancy surface
  reachesSelfdestruct: boolean;
  usesTxOrigin: boolean; // tx.origin seen — spoofable auth if used as a guard
}

/**
 * Walk a function handler from its entry PC, following static jumps within a
 * bounded budget, to summarise its state/access behaviour.
 */
export function analyzeHandler(instrs: Instr[], byPc: Map<number, number>, startPc: number): HandlerAnalysis {
  const res: HandlerAnalysis = {
    writesState: false,
    callerBeforeWrite: false,
    hasExternalCall: false,
    stateChangeAfterCall: false,
    reachesSelfdestruct: false,
    usesTxOrigin: false,
  };
  const seen = new Set<number>();
  const stack: { pc: number; caller: boolean; called: boolean }[] = [{ pc: startPc, caller: false, called: false }];
  let budget = 4000;

  while (stack.length && budget-- > 0) {
    const frame = stack.pop()!;
    let idx = byPc.get(frame.pc);
    if (idx == null) continue;
    let callerSeen = frame.caller;
    let called = frame.called;

    for (; idx < instrs.length && budget-- > 0; idx++) {
      const ins = instrs[idx];
      if (seen.has(ins.pc)) break;
      seen.add(ins.pc);
      const op = ins.op;

      if (op === OP.CALLER) callerSeen = true;
      else if (op === OP.ORIGIN) res.usesTxOrigin = true;
      else if (op === OP.SSTORE) {
        res.writesState = true;
        if (callerSeen) res.callerBeforeWrite = true;
        if (called) res.stateChangeAfterCall = true;
      } else if (op === OP.CALL || op === OP.CALLCODE || op === OP.DELEGATECALL) {
        res.hasExternalCall = true;
        called = true;
      } else if (op === OP.SELFDESTRUCT) {
        res.reachesSelfdestruct = true;
      }

      if (op === OP.JUMP) {
        const prev = instrs[idx - 1];
        if (prev && prev.op >= 0x60 && prev.op <= 0x7f && prev.push) {
          stack.push({ pc: parseInt(prev.push, 16), caller: callerSeen, called });
        }
        break; // unconditional jump ends this straight-line block
      }
      if (op === OP.JUMPI) {
        const prev = instrs[idx - 1];
        if (prev && prev.op >= 0x60 && prev.op <= 0x7f && prev.push) {
          stack.push({ pc: parseInt(prev.push, 16), caller: callerSeen, called });
        }
        // fall through to the not-taken branch
      }
      if (op === OP.STOP || op === OP.RETURN || op === OP.REVERT || op === OP.INVALID || op === OP.SELFDESTRUCT) break;
    }
  }
  return res;
}

export interface ContractAnalysis {
  /** per selector-of-interest: its handler analysis (undefined = selector not found in dispatcher) */
  fns: Record<string, HandlerAnalysis | undefined>;
  /** contract-wide: reachable selfdestruct anywhere */
  hasSelfdestruct: boolean;
  /** dispatcher was parseable at all */
  dispatchFound: boolean;
}

/**
 * Analyze specific selectors of interest (the dangerous ones) plus a couple of
 * well-known "seize the contract" entrypoints.
 */
export function analyzeContract(codeHex: string, selectors: string[]): ContractAnalysis {
  const instrs = disassemble(codeHex);
  const byPc = new Map(instrs.map((ins, i) => [ins.pc, i]));
  const dispatch = buildDispatch(instrs);
  const fns: Record<string, HandlerAnalysis | undefined> = {};
  for (const sel of selectors) {
    const pc = dispatch.get(sel.toLowerCase());
    fns[sel.toLowerCase()] = pc != null ? analyzeHandler(instrs, byPc, pc) : undefined;
  }
  const hasSelfdestruct = instrs.some((i) => i.op === OP.SELFDESTRUCT);
  return { fns, hasSelfdestruct, dispatchFound: dispatch.size > 0 };
}

/** Selectors of "should be privileged" functions we check for missing guards. */
export const GUARD_CHECK_SELECTORS: Record<string, string> = {
  '0x40c10f19': 'mint(address,uint256)',
  '0xa0712d68': 'mint(uint256)',
  '0x6a627842': 'mint(address)',
  '0xe30443bc': 'setBalance(address,uint256)',
  '0xe0b1cccb': 'updateBalance(address,uint256)',
  '0xf2fde38b': 'transferOwnership(address)',
  '0x8129fc1c': 'initialize()',
  '0x4cd88b76': 'initialize(string,string)',
  '0xc4d66de8': 'initialize(address)',
  '0xf9f92be4': 'blacklist(address)',
  '0x69fe0e2d': 'setFee(uint256)',
  '0x8456cb59': 'pause()',
  '0xc2e5ec04': 'setTradingEnabled(bool)',
};

const INIT_SELECTORS = ['0x8129fc1c', '0x4cd88b76', '0xc4d66de8'];

/** Finding-friendly summary of what a random non-owner can do to this contract. */
export interface CodeVulns {
  /** by risk CLASS: is the privileged fn access-controlled? true=guarded, false=UNGUARDED (anyone), null=absent/unknown */
  guard: Record<string, boolean | null>;
  /** an initialize() that writes state with no caller check — anyone can seize/re-init */
  unprotectedInit: string | null;
  /** SELFDESTRUCT reachable from a function with no caller check — anyone can brick it */
  publicSelfdestruct: boolean;
  /** functions that change state AFTER an external call — reentrancy surface */
  reentrancy: string[];
  /** transferOwnership reachable with no caller check — anyone can seize ownership */
  unguardedOwnershipXfer: string | null;
  /** a privileged fn authenticates via tx.origin — spoofable through a malicious contract */
  txOriginAuth: string | null;
  /** did we manage to parse a dispatcher at all (low => analysis is unreliable) */
  analyzable: boolean;
}

/**
 * Derive the non-owner-exploit signals for a contract.
 * @param classSelectors  map of risk CLASS -> its selectors (with 0x prefix)
 */
export function deriveVulns(codeHex: string, classSelectors: Record<string, string[]>): CodeVulns {
  const allSels = [
    ...new Set([...Object.values(classSelectors).flat(), ...Object.keys(GUARD_CHECK_SELECTORS)].map((s) => s.toLowerCase())),
  ];
  const c = analyzeContract(codeHex, allSels);

  // "Open to anyone" = writes state with NO caller check AND not even a
  // tx.origin check. A tx.origin check still limits who can ultimately trigger
  // it (just spoofably), so it is reported under txOriginAuth, not as unguarded.
  const openToAnyone = (f: HandlerAnalysis) => f.writesState && !f.callerBeforeWrite && !f.usesTxOrigin;

  const guard: Record<string, boolean | null> = {};
  for (const [cls, sels] of Object.entries(classSelectors)) {
    let verdict: boolean | null = null;
    for (const sel of sels) {
      const f = c.fns[sel.toLowerCase()];
      if (!f || !f.writesState) continue;
      if (openToAnyone(f)) {
        verdict = false; // UNGUARDED wins outright
        break;
      }
      verdict = true;
    }
    guard[cls] = verdict;
  }

  let unprotectedInit: string | null = null;
  for (const sel of INIT_SELECTORS) {
    const f = c.fns[sel];
    if (f && openToAnyone(f)) {
      unprotectedInit = GUARD_CHECK_SELECTORS[sel];
      break;
    }
  }

  let publicSelfdestruct = false;
  for (const f of Object.values(c.fns)) {
    if (f && f.reachesSelfdestruct && !f.callerBeforeWrite && !f.usesTxOrigin) {
      publicSelfdestruct = true;
      break;
    }
  }

  const reentrancy: string[] = [];
  for (const [sel, f] of Object.entries(c.fns)) {
    if (f && f.stateChangeAfterCall) reentrancy.push(GUARD_CHECK_SELECTORS[sel] || sel);
  }

  // anyone can seize ownership via an unguarded transferOwnership
  let unguardedOwnershipXfer: string | null = null;
  const xfer = c.fns['0xf2fde38b'];
  if (xfer && openToAnyone(xfer)) unguardedOwnershipXfer = 'transferOwnership(address)';

  // a privileged fn that authenticates via tx.origin can be spoofed by a contract
  let txOriginAuth: string | null = null;
  for (const [sel, f] of Object.entries(c.fns)) {
    if (f && f.writesState && f.usesTxOrigin) {
      txOriginAuth = GUARD_CHECK_SELECTORS[sel] || sel;
      break;
    }
  }

  return { guard, unprotectedInit, publicSelfdestruct, reentrancy, unguardedOwnershipXfer, txOriginAuth, analyzable: c.dispatchFound };
}
