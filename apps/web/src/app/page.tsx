/**
 * Server component: does the first query on the server so the table paints
 * with real rows instead of a spinner, then hands off to the client component
 * for filtering and infinite scroll.
 */
import { and, desc, eq, gte, sql } from 'drizzle-orm';
import { pools, tokens, scanRuns } from '@liqarch/shared';
import { db } from '@/lib/db';
import Dashboard, { type Row } from '@/components/Dashboard';

export const dynamic = 'force-dynamic';

async function safe<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await fn();
  } catch {
    // An unmigrated or unreachable database should render an empty dashboard
    // with a hint, not a 500 page.
    return fallback;
  }
}

export default async function Page() {
  const rows = await safe<Row[]>(
    () =>
      db
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
        .leftJoin(sql`${tokens} as t1`, sql`t1.address = ${pools.token1}`)
        .where(and(eq(pools.passesThreshold, true), gte(pools.lockedLiquidityUsd, 100)))
        .orderBy(desc(pools.lockedLiquidityUsd))
        .limit(100) as unknown as Promise<Row[]>,
    [],
  );

  const stats = await safe(async () => {
    const [agg] = await db
      .select({
        passing: sql<number>`count(*)::int`,
        totalLocked: sql<number>`coalesce(sum(${pools.lockedLiquidityUsd}), 0)::float8`,
      })
      .from(pools)
      .where(eq(pools.passesThreshold, true));
    const [run] = await db.select().from(scanRuns).orderBy(desc(scanRuns.id)).limit(1);
    return {
      passing: agg?.passing ?? 0,
      totalLocked: agg?.totalLocked ?? 0,
      discovered: run?.poolsDiscovered ?? 0,
    };
  }, { passing: 0, totalLocked: 0, discovered: 0 });

  return <Dashboard initialRows={rows} stats={stats} />;
}
