/**
 * Query API for the dashboard table.
 *
 * Keyset pagination (cursor on locked_liquidity_usd) rather than OFFSET —
 * OFFSET degrades linearly and the whole point of this table is that you can
 * scroll deep into 40k+ rows without the UI stalling.
 */
import { NextResponse } from 'next/server';
import { and, desc, eq, gte, lte, lt, or, sql, ilike } from 'drizzle-orm';
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
  const q = p.get('q'); // free-text on symbol / address
  const cursor = p.get('cursor') ? Number(p.get('cursor')) : null;

  const where = [eq(pools.passesThreshold, true), gte(pools.lockedLiquidityUsd, minUsd)];

  if (maxUsd != null) where.push(lte(pools.lockedLiquidityUsd, maxUsd));
  if (minLockedPct != null) where.push(gte(pools.lockedFraction, minLockedPct));
  if (kind) where.push(eq(pools.kind, kind));
  if (factory) where.push(eq(pools.factory, factory.toLowerCase()));
  if (before != null) where.push(lte(pools.createdBlock, before));

  // "Burned" is the strict, provable subset: LP at a dead address.
  if (lockType === 'burned') where.push(gte(pools.burnedLiquidityUsd, minUsd));
  if (lockType === 'locked') where.push(sql`${pools.lpLockedKnown}::numeric + ${pools.lpLockedUnknownContract}::numeric > 0`);

  // Keyset cursor.
  if (cursor != null) where.push(lt(pools.lockedLiquidityUsd, cursor));

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
      lockedLiquidityUsd: pools.lockedLiquidityUsd,
      burnedLiquidityUsd: pools.burnedLiquidityUsd,
      lockedFraction: pools.lockedFraction,
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
    .orderBy(desc(pools.lockedLiquidityUsd))
    .limit(PAGE + 1);

  const hasMore = rows.length > PAGE;
  const page = hasMore ? rows.slice(0, PAGE) : rows;

  return NextResponse.json({
    rows: page,
    nextCursor: hasMore ? page[page.length - 1].lockedLiquidityUsd : null,
  });
}
