/**
 * Persistence.
 *
 * Only pools that PASS the threshold are written to Postgres. That is a
 * deliberate ~20x reduction in write volume: pushing 1.2M discovered pools to a
 * remote database would dominate total scan time and add nothing, since the
 * full discovery output already lives in data/pools.ndjson for re-runs.
 *
 * Writes go in chunks via a single multi-row INSERT ... ON CONFLICT so that
 * re-running a scan updates in place instead of duplicating.
 */
import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { sql } from 'drizzle-orm';
import { pools, lpHolders, scanRuns } from '@liqarch/shared';
import type { PoolWithLocks } from './types.js';
import { logger } from './log.js';

let _db: ReturnType<typeof drizzle> | null = null;

export function db() {
  if (_db) return _db;
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error('DATABASE_URL is not set — see .env.example');
  _db = drizzle(postgres(url, { max: 8, prepare: false }));
  return _db;
}

export async function startRun(o: { fromBlock: number; toBlock: number; thresholdUsd: number }) {
  const [row] = await db()
    .insert(scanRuns)
    .values({ fromBlock: o.fromBlock, toBlock: o.toBlock, thresholdUsd: o.thresholdUsd, status: 'running', stage: 'discovery' })
    .returning({ id: scanRuns.id });
  logger.info(`scan run #${row.id} started`);
  return row.id;
}

export async function finishRun(
  id: number,
  o: { poolsDiscovered: number; poolsPriced: number; poolsPassing: number; ethPriceUsd: number; timings: unknown },
) {
  await db()
    .update(scanRuns)
    .set({ status: 'done', finishedAt: new Date(), stage: 'done', ...o, timings: o.timings as object })
    .where(sql`${scanRuns.id} = ${id}`);
}

/** Bump the running scan's counters mid-flight so the dashboard updates live. */
export async function updateRunProgress(
  id: number,
  o: { stage?: string; poolsDiscovered?: number; poolsPriced?: number; poolsPassing?: number; ethPriceUsd?: number },
) {
  await db()
    .update(scanRuns)
    .set({ ...o })
    .where(sql`${scanRuns.id} = ${id}`);
}

export async function failRun(id: number, error: string) {
  await db()
    .update(scanRuns)
    .set({ status: 'failed', finishedAt: new Date(), error })
    .where(sql`${scanRuns.id} = ${id}`);
}

// --- token risk (stage 4) --------------------------------------------------

export interface RiskUpdate {
  address: string; // pool address
  riskScore: number;
  riskTier: string;
  riskFlags: string[];
  riskFindings: unknown[];
}

/** Load survivors so risk analysis can backfill them without re-scanning. */
export async function loadPassingPools(): Promise<
  { address: string; token0: string; token1: string; quoteSide: number | null; lockedLiquidityUsd: number | null }[]
> {
  return db()
    .select({
      address: pools.address,
      token0: pools.token0,
      token1: pools.token1,
      quoteSide: pools.quoteSide,
      lockedLiquidityUsd: pools.lockedLiquidityUsd,
    })
    .from(pools)
    .where(sql`${pools.passesThreshold} = true`);
}

/** Bulk-write risk fields onto existing pool rows (one UPDATE ... FROM VALUES per chunk). */
export async function persistRisk(updates: RiskUpdate[]) {
  if (updates.length === 0) return;
  const d = db();
  const CH = 500;
  for (let i = 0; i < updates.length; i += CH) {
    const slice = updates.slice(i, i + CH);
    const rows = slice.map(
      (u) =>
        sql`(${u.address.toLowerCase()}, ${u.riskScore}::int, ${u.riskTier}::text, ${JSON.stringify(
          u.riskFlags,
        )}::jsonb, ${JSON.stringify(u.riskFindings)}::jsonb)`,
    );
    await d.execute(sql`
      update ${pools} as p set
        risk_score    = v.score,
        risk_tier     = v.tier,
        risk_flags    = v.flags,
        risk_findings = v.findings
      from (values ${sql.join(rows, sql`, `)}) as v(address, score, tier, flags, findings)
      where p.address = v.address
    `);
  }
}

const CHUNK = 500;

export async function persist(results: PoolWithLocks[], scanRunId: number) {
  if (results.length === 0) {
    logger.warn('nothing passed the threshold — nothing to persist');
    return;
  }

  const d = db();

  for (let i = 0; i < results.length; i += CHUNK) {
    const slice = results.slice(i, i + CHUNK);

    await d
      .insert(pools)
      .values(
        slice.map((p) => ({
          address: p.address,
          kind: p.kind,
          factory: p.factory,
          token0: p.token0,
          token1: p.token1,
          feeTier: p.feeTier,
          createdBlock: p.createdBlock,
          createdAt: p.createdTs ? new Date(p.createdTs * 1000) : null,
          createdTx: p.createdTx,
          quoteSide: p.quoteSide,
          reserve0: p.reserve0.toString(),
          reserve1: p.reserve1.toString(),
          lpTotalSupply: p.lpTotalSupply.toString(),
          totalLiquidityUsd: p.totalLiquidityUsd,
          lpBurned: p.lpBurned.toString(),
          lpLockedKnown: p.lpLockedKnown.toString(),
          lpLockedUnknownContract: p.lpLockedUnknownContract.toString(),
          lockedFraction: p.lockedFraction,
          lockedLiquidityUsd: p.lockedLiquidityUsd,
          burnedLiquidityUsd: p.burnedLiquidityUsd,
          earliestUnlockAt: p.earliestUnlockAt,
          passesThreshold: true,
          scanRunId,
          updatedAt: new Date(),
        })),
      )
      .onConflictDoUpdate({
        target: pools.address,
        set: {
          reserve0: sql`excluded.reserve0`,
          reserve1: sql`excluded.reserve1`,
          totalLiquidityUsd: sql`excluded.total_liquidity_usd`,
          lockedFraction: sql`excluded.locked_fraction`,
          lockedLiquidityUsd: sql`excluded.locked_liquidity_usd`,
          burnedLiquidityUsd: sql`excluded.burned_liquidity_usd`,
          scanRunId: sql`excluded.scan_run_id`,
          updatedAt: sql`excluded.updated_at`,
        },
      });

    const holderRows = slice.flatMap((p) =>
      p.holders.map((h) => ({
        pool: p.address,
        holder: h.holder,
        balance: h.balance.toString(),
        fraction: h.fraction,
        classification: h.classification,
        lockerName: h.lockerName,
        unlockAt: h.unlockAt,
      })),
    );

    if (holderRows.length) {
      await d.insert(lpHolders).values(holderRows).onConflictDoNothing();
    }

    logger.info(`  persisted ${Math.min(i + CHUNK, results.length).toLocaleString()}/${results.length.toLocaleString()}`);
  }
}
