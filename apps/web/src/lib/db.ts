import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';

// Cached across hot reloads so dev doesn't exhaust the connection pool.
const g = globalThis as unknown as { _sql?: ReturnType<typeof postgres> };
const client = g._sql ?? postgres(process.env.DATABASE_URL!, { max: 4, prepare: false });
if (process.env.NODE_ENV !== 'production') g._sql = client;

export const db = drizzle(client);
