# liquidity archaeologist

Finds Ethereum tokens launched **before 2024** that still have **≥ $100 of locked or burned liquidity** sitting in their pools.

The target: dead memecoins, abandoned communities, and half-finished rugs where the dev pulled what they could and the locked remainder is still stranded on-chain.

---

## How it hits the speed target

Scanning "all pre-2024 token launches" naively means walking 18.9M blocks. That's days. Four decisions collapse it to minutes:

**1. Don't scan blocks — scan one topic.**
Pool creations are events. We pull `PairCreated` + `PoolCreated` logs via [Envio HyperSync](https://docs.envio.dev), which is purpose-built for exactly this and returns ~1M+ results in single-digit minutes.

**2. Don't enumerate DEXes — discover them.**
We filter by **topic0 only, with no factory address filter**. Every Uniswap V2 fork ever deployed emits the identical `PairCreated` signature, so one topic scan catches Uniswap, SushiSwap, ShibaSwap, PancakeSwap-on-ETH, Fraxswap *and the several hundred one-off forks nobody has catalogued*. The factory address is an **output** of the scan, not an input. This is what "all DEXes" actually requires — a hardcoded list can only ever find DEXes we already knew about.

**3. No archive node required.**
We only care about liquidity that survives *right now*, so all state reads hit current state. This is the single biggest cost saver — archive access is where blockchain scanners get expensive.

**4. Narrow before every escalation in cost.**

| stage | cost per pool | remaining |
|---|---|---|
| discovery (topic sweep) | ~0 | ~1.2M |
| has a priceable quote side | 0 | ~350K |
| valuation (3 batched calls) | cheap | ~60K |
| lock analysis (full LP history replay) | expensive | ~40K |

Lock analysis runs on the ~60K survivors, not the 1.2M. Reversing that order costs ~20× more wall-clock for an identical answer.

---

## What "locked" actually means here

There is no `isLocked()` to call. It gets reconstructed:

1. Pull the complete ERC-20 `Transfer` history of each surviving pool's **LP token**.
2. Replay it to get exact per-holder LP balances — exact, not sampled.
3. Classify every holder:

| class | meaning |
|---|---|
| `burned` | LP at `0x0` / `0xdead`. Provably unrecoverable, forever. |
| `locker_known` | Held by a locker in our registry (UNCX, Team Finance, PinkLock…). |
| `locker_unknown_contract` | Address **has bytecode**. Not withdrawable by a keyholder on a whim. |
| `eoa` | A plain wallet. Can rug at any moment. |

4. `lockedLiquidityUsd = totalLiquidityUsd × (burned + locked) / lpTotalSupply`

**The contract-vs-EOA check is why this works without a perfect locker registry.** Any hardcoded address list misses the long tail of custom 2020–2022 lockers. "Does this address have code" never does.

> ⚠️ **The locker addresses in `constants.ts` are marked `verified: false`.** They were written from memory and are **not confirmed against a primary source**. Run `pnpm --filter @liqarch/indexer verify-lockers` to check each one has bytecode before trusting the labels. Coverage does not depend on them — structural detection catches those pools either way; the registry only improves *labelling*.

### Pricing needs zero API keys

A pool is priceable if one side is WETH/USDC/USDT/DAI/FRAX. Constant-product pools hold equal value on both sides, so `poolUsd = 2 × quoteSideUsd`. ETH/USD comes from the **Chainlink feed read on-chain**. No CoinGecko, no rate limits, no key.

Pools with no quote-asset side (e.g. SHIB/PEPE) are marked unpriceable rather than guessed at. Deriving prices recursively through the pool graph is a real feature, but it's also a reliable way to produce confident nonsense from one manipulated pool. Deliberately left as follow-up.

---

## Setup

```bash
pnpm install
cp .env.example .env      # then fill it in
pnpm db:push              # create tables
pnpm scan                 # full pre-2024 sweep
pnpm dev                  # dashboard at localhost:3000
```

### What you need to get

| what | where | cost |
|---|---|---|
| **Envio API token** | [envio.dev/app/api-tokens](https://envio.dev/app/api-tokens) | free tier is fine |
| **RPC endpoints** | Alchemy / Ankr / drpc / LlamaRPC / PublicNode | free tiers work |
| **Postgres** | Supabase, Neon, or `docker run postgres` | free tier is fine |

**On RPC: more endpoints beats a bigger plan.** The multicall engine round-robins across every URL in `RPC_URLS` with per-endpoint concurrency caps. Four free keys from four providers will out-throughput one paid key, because the binding constraint is per-provider rate limiting, not bandwidth. Start with the three public endpoints in `.env.example`, add an Alchemy free key, and you're done.

**You do not need a websocket.** Websockets are for live tailing. This is a historical scan against current state — plain HTTPS RPC plus HyperSync is strictly faster here.

### Tuning

```bash
pnpm scan --min-usd 500        # different threshold
pnpm scan --skip-discovery     # reuse data/pools.ndjson, re-run valuation only
pnpm scan --to 18908895        # different cutoff block
```

`--skip-discovery` matters: discovery is the expensive part and its full output is kept on disk, so *"actually, make it $50"* is a 2-minute re-run rather than a 2-hour one.

---

## Layout

```
packages/shared/     constants, ABIs, Drizzle schema  (single source of truth)
apps/indexer/
  stages/01-discover.ts   HyperSync topic sweep
  stages/02-value.ts      batched multicall + Chainlink pricing
  stages/03-locks.ts      LP history replay + holder classification
  lib/multicall.ts        the throughput engine
apps/web/            Next.js dashboard, virtualized table, keyset pagination
```

Everything is env-var driven and vendor-neutral. The database layer is plain Postgres via Drizzle — Supabase, Neon, RDS, and local Docker are all drop-in.

---

## Known gaps

Being explicit so nobody trusts something that hasn't been earned:

- **Not yet run end-to-end.** Written in an environment with no npm registry access, so it has never been executed. Expect to shake out import and type errors on first `pnpm install && pnpm typecheck`.
- **Locker addresses unverified** — see the warning above.
- **V3 pools are discovered but not valued.** Concentrated liquidity needs tick-range math to value a position; V2 covers the overwhelming majority of pre-2024 launches and is handled exactly. Approximating V3 badly would be worse than skipping it.
- **Balancer / Curve** use different pool architectures and aren't covered by the two topic signatures.
- **Token metadata backfill** (`name`/`symbol`, incl. the `bytes32` variant old tokens use) is written but not yet wired into the scan loop.
