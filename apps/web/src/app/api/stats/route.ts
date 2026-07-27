import { NextResponse } from 'next/server';
import { desc, eq, sql } from 'drizzle-orm';
import { pools, scanRuns } from '@liqarch/shared';
import { db } from '@/lib/db';

export const dynamic = 'force-dynamic';

// Live header stats. The dashboard polls this so the "pools / locked / scanned"
// counters and the running indicator update while a scan is in flight.
export async function GET() {
  try {
    const [agg] = await db
      .select({
        passing: sql<number>`count(*)::int`,
        // Clamp each pool's locked to its own total before summing. A locked
        // fraction can't exceed 1, but stale/near-zero LP totalSupply can make
        // the stored figure explode (locked >> total). LEAST() sanitizes those
        // so the headline can't read $2e22 off a handful of bad rows.
        totalLocked: sql<number>`coalesce(sum(least(${pools.lockedLiquidityUsd}, ${pools.totalLiquidityUsd})), 0)::float8`,
      })
      .from(pools)
      .where(eq(pools.passesThreshold, true));

    const [run] = await db.select().from(scanRuns).orderBy(desc(scanRuns.id)).limit(1);

    return NextResponse.json({
      passing: agg?.passing ?? 0,
      totalLocked: agg?.totalLocked ?? 0,
      discovered: run?.poolsDiscovered ?? 0,
      running: run?.status === 'running',
      stage: run?.stage ?? null,
    });
  } catch {
    return NextResponse.json({ passing: 0, totalLocked: 0, discovered: 0, running: false, stage: null });
  }
}
