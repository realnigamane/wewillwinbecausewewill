import { NextResponse } from 'next/server';
import { desc, eq } from 'drizzle-orm';
import { lpHolders } from '@liqarch/shared';
import { db } from '@/lib/db';

export const dynamic = 'force-dynamic';

export async function GET(_req: Request, { params }: { params: Promise<{ pool: string }> }) {
  const { pool } = await params;
  try {
    const holders = await db
      .select()
      .from(lpHolders)
      .where(eq(lpHolders.pool, pool.toLowerCase()))
      .orderBy(desc(lpHolders.fraction))
      .limit(25);
    return NextResponse.json({ holders });
  } catch {
    return NextResponse.json({ holders: [] });
  }
}
