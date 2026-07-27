/**
 * Query API for the dashboard table.
 *
 * Keyset pagination (cursor on locked_liquidity_usd) rather than OFFSET —
 * OFFSET degrades linearly and the whole point of this table is that you can
 * scroll deep into 40k+ rows without the UI stalling.
 */
import { NextResponse } from 'next/server';
import { and, eq, gte, lte, or, sql, ilike } from 'drizzle-orm';
import { pools, tokens } from '@liqarch/shared';
import { db } from '@/lib/db';

export const dynamic = 'force-dynamic';

const PAGE = 100;

export async function GET(req: Request) {
  const p = new URL(req.url).searchParams;

  const minUsd = Number(p.get('minUsd') ?? '100');
  const maxUsd = p.get('maxUsd') ? Number(p.get('maxUsd')) : null;
  const minLockedPct = p.get('minLockedPct') ? Number(p.get('minLockedPct')) / 100 : null;
  const lockType = p.get('lockType'); // 'burned' | 'locked' | null
  const kind = p.get('kind'); // 'v2' | 'v3'
  const factory = p.get('factory');
  const before = p.get('before') ? Number(p.get('before')) : null; // created-block ceiling
  const after = p.get('after') ? Number(p.get('after')) : null; // created-block floor (age band)
  const q = p.get('q'); // free-text on symbol / address
  const cursor = p.get('cursor') ? Number(p.get('cursor')) : null;
  const minRisk = p.get('minRisk') ? Number(p.get('minRisk')) : null;

  // Locked liquidity can never exceed the pool's own total. Some stored rows
  // violate that (near-zero or stale LP totalSupply blows the fraction past 1,
  // yielding locked >> total — up to ~1e22). Clamp on read so every filter,
  // sort, and displayed figure uses a sane value without needing a re-scan.
  const lockedClamped = sql<number>`least(${pools.lockedLiquidityUsd}, ${pools.totalLiquidityUsd})`;
  const burnedClamped = sql<number>`least(${pools.burnedLiquidityUsd}, ${pools.totalLiquidityUsd})`;
  const fractionClamped = sql<number>`least(${pools.lockedFraction}, 1)`;

  const where = [eq(pools.passesThreshold, true), sql`least(${pools.lockedLiquidityUsd}, ${pools.totalLiquidityUsd}) >= ${minUsd}`];

  if (maxUsd != null) where.push(sql`least(${pools.lockedLiquidityUsd}, ${pools.totalLiquidityUsd}) <= ${maxUsd}`);
  if (minLockedPct != null) where.push(gte(pools.lockedFraction, minLockedPct));
  if (kind) where.push(eq(pools.kind, kind));
  if (factory) where.push(eq(pools.factory, factory.toLowerCase()));
  if (before != null) where.push(lte(pools.createdBlock, before));
  if (after != null) where.push(gte(pools.createdBlock, after));
  if (minRisk != null) where.push(gte(pools.riskScore, minRisk));

  // "Burned" is the strict, provable subset: LP at a dead address.
  if (lockType === 'burned') where.push(sql`least(${pools.burnedLiquidityUsd}, ${pools.totalLiquidityUsd}) >= ${minUsd}`);
  if (lockType === 'locked') where.push(sql`${pools.lpLockedKnown}::numeric + ${pools.lpLockedUnknownContract}::numeric > 0`);

  // Keyset cursor — on the SAME clamped expression the rows are ordered by.
  if (cursor != null) where.push(sql`least(${pools.lockedLiquidityUsd}, ${pools.totalLiquidityUsd}) < ${cursor}`);

  const base = db
    .select({
      address: pools.address,
      kind: pools.kind,
      factory: pools.factory,
      dexName: pools.dexName,
      token0: pools.token0,
      token1: pools.token1,
      createdBlock: pools.createdBlock,
      createdAt: pools.createdAt,
      totalLiquidityUsd: pools.totalLiquidityUsd,
      lockedLiquidityUsd: lockedClamped,
      burnedLiquidityUsd: burnedClamped,
      lockedFraction: fractionClamped,
      riskScore: pools.riskScore,
      riskTier: pools.riskTier,
      riskFlags: pools.riskFlags,
      riskFindings: pools.riskFindings,
      symbol0: sql<string>`t0.symbol`,
      symbol1: sql<string>`t1.symbol`,
      name0: sql<string>`t0.name`,
      name1: sql<string>`t1.name`,
    })
    .from(pools)
    .leftJoin(sql`${tokens} as t0`, sql`t0.address = ${pools.token0}`)
    .leftJoin(sql`${tokens} as t1`, sql`t1.address = ${pools.token1}`);

  if (q) {
    const needle = `%${q}%`;
    where.push(
      or(
        ilike(sql`t0.symbol`, needle),
        ilike(sql`t1.symbol`, needle),
        ilike(pools.address, needle),
        ilike(pools.token0, needle),
        ilike(pools.token1, needle),
      )!,
    );
  }

  const rows = await base
    .where(and(...where))
    // Order by the clamped value so the former >>total offenders sort by their
    // real (clamped) locked amount, not the astronomical raw figure.
    .orderBy(sql`least(${pools.lockedLiquidityUsd}, ${pools.totalLiquidityUsd}) desc`)
    .limit(PAGE + 1);

  const hasMore = rows.length > PAGE;
  const page = hasMore ? rows.slice(0, PAGE) : rows;

  return NextResponse.json({
    rows: page,
    nextCursor: hasMore ? page[page.length - 1].lockedLiquidityUsd : null,
  });
}
