/**
 * Drizzle schema. Targets plain Postgres, so it runs identically against
 * Supabase, Neon, RDS, or a local `docker run postgres`. Nothing here is
 * vendor-specific.
 */
import {
  pgTable,
  text,
  integer,
  bigint,
  doublePrecision,
  boolean,
  timestamp,
  numeric,
  index,
  uniqueIndex,
  jsonb,
  primaryKey,
} from 'drizzle-orm/pg-core';

/**
 * Every pool discovered by the topic0 sweep, before filtering.
 *
 * We keep the losers too (with `passes_threshold = false`) because re-running
 * discovery is the expensive part; re-running valuation against a stored pool
 * list is cheap. This makes "change the threshold to $50" a 2-minute operation
 * instead of a 2-hour one.
 */
export const pools = pgTable(
  'pools',
  {
    address: text('address').primaryKey(),

    // --- discovery (stage 1) ---
    kind: text('kind').notNull(), // 'v2' | 'v3'
    factory: text('factory').notNull(),
    dexName: text('dex_name'), // resolved from factory address, null for unknown forks
    token0: text('token0').notNull(),
    token1: text('token1').notNull(),
    feeTier: integer('fee_tier'), // v3 only
    createdBlock: bigint('created_block', { mode: 'number' }).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }),
    createdTx: text('created_tx'),

    // --- valuation (stage 2) ---
    /** Which side of the pair is the priceable quote asset: 0, 1, or null if neither. */
    quoteSide: integer('quote_side'),
    reserve0: numeric('reserve0', { precision: 78, scale: 0 }),
    reserve1: numeric('reserve1', { precision: 78, scale: 0 }),
    lpTotalSupply: numeric('lp_total_supply', { precision: 78, scale: 0 }),
    /** Full pool value in USD (both sides). */
    totalLiquidityUsd: doublePrecision('total_liquidity_usd'),

    // --- lock analysis (stage 3) ---
    lpBurned: numeric('lp_burned', { precision: 78, scale: 0 }),
    lpLockedKnown: numeric('lp_locked_known', { precision: 78, scale: 0 }),
    lpLockedUnknownContract: numeric('lp_locked_unknown_contract', { precision: 78, scale: 0 }),
    /** (burned + locked) / totalSupply, 0..1 */
    lockedFraction: doublePrecision('locked_fraction'),
    /** totalLiquidityUsd * lockedFraction — THE number this whole tool exists to compute. */
    lockedLiquidityUsd: doublePrecision('locked_liquidity_usd'),
    /** Strictest signal: LP provably at a dead address. */
    burnedLiquidityUsd: doublePrecision('burned_liquidity_usd'),
    earliestUnlockAt: timestamp('earliest_unlock_at', { withTimezone: true }),

    passesThreshold: boolean('passes_threshold').default(false).notNull(),

    // --- token risk / bug-bounty analysis (stage 4) ---
    // Scored on the memecoin (non-quote) side of the pair.
    riskScore: integer('risk_score'), // 0..100, null = not yet analyzed
    riskTier: text('risk_tier'), // clean | low | medium | high | critical
    riskFlags: jsonb('risk_flags').$type<string[]>(),
    /** Detailed per-contract findings (attack path + assessment) for the detail panel. */
    riskFindings: jsonb('risk_findings'),

    scanRunId: integer('scan_run_id'),
    lastScannedBlock: bigint('last_scanned_block', { mode: 'number' }),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
  },
  (t) => ({
    // The dashboard's default view: survivors sorted by locked value.
    byLocked: index('pools_locked_idx').on(t.passesThreshold, t.lockedLiquidityUsd),
    byCreated: index('pools_created_idx').on(t.createdBlock),
    byToken0: index('pools_token0_idx').on(t.token0),
    byToken1: index('pools_token1_idx').on(t.token1),
    byFactory: index('pools_factory_idx').on(t.factory),
  }),
);

/** Token metadata, deduped across pools (one token can appear in dozens of pools). */
export const tokens = pgTable(
  'tokens',
  {
    address: text('address').primaryKey(),
    name: text('name'),
    symbol: text('symbol'),
    decimals: integer('decimals'),
    totalSupply: numeric('total_supply', { precision: 78, scale: 0 }),
    /** Bytecode size. 0 means self-destructed or never a contract — a strong dead-token signal. */
    codeSize: integer('code_size'),
    isVerifiedSource: boolean('is_verified_source'),
    metadataOk: boolean('metadata_ok').default(false).notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
  },
  (t) => ({ bySymbol: index('tokens_symbol_idx').on(t.symbol) }),
);

/** Per-holder breakdown of who holds a pool's LP. Only stored for pools that pass. */
export const lpHolders = pgTable(
  'lp_holders',
  {
    pool: text('pool').notNull(),
    holder: text('holder').notNull(),
    balance: numeric('balance', { precision: 78, scale: 0 }).notNull(),
    fraction: doublePrecision('fraction').notNull(),
    /** 'burned' | 'locker_known' | 'locker_unknown_contract' | 'eoa' */
    classification: text('classification').notNull(),
    lockerName: text('locker_name'),
    unlockAt: timestamp('unlock_at', { withTimezone: true }),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.pool, t.holder] }),
    byPool: index('lp_holders_pool_idx').on(t.pool),
  }),
);

/** One row per scan invocation. Drives the live progress UI. */
export const scanRuns = pgTable('scan_runs', {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  startedAt: timestamp('started_at', { withTimezone: true }).defaultNow().notNull(),
  finishedAt: timestamp('finished_at', { withTimezone: true }),
  status: text('status').notNull().default('running'), // running | done | failed
  stage: text('stage'),
  fromBlock: bigint('from_block', { mode: 'number' }),
  toBlock: bigint('to_block', { mode: 'number' }),
  thresholdUsd: doublePrecision('threshold_usd'),
  poolsDiscovered: integer('pools_discovered').default(0).notNull(),
  poolsPriced: integer('pools_priced').default(0).notNull(),
  poolsPassing: integer('pools_passing').default(0).notNull(),
  ethPriceUsd: doublePrecision('eth_price_usd'),
  error: text('error'),
  timings: jsonb('timings'),
});

/** Factories discovered during the sweep — an output, not an input. */
export const factories = pgTable('factories', {
  address: text('address').primaryKey(),
  kind: text('kind').notNull(),
  name: text('name'),
  poolCount: integer('pool_count').default(0).notNull(),
  firstBlock: bigint('first_block', { mode: 'number' }),
});

export type Pool = typeof pools.$inferSelect;
export type Token = typeof tokens.$inferSelect;
export type LpHolder = typeof lpHolders.$inferSelect;
export type ScanRun = typeof scanRuns.$inferSelect;
export type Factory = typeof factories.$inferSelect;
