const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 } as const;
const active = LEVELS[(process.env.LOG_LEVEL as keyof typeof LEVELS) ?? 'info'] ?? 20;
const t0 = Date.now();

function emit(level: keyof typeof LEVELS, msg: string) {
  if (LEVELS[level] < active) return;
  const el = ((Date.now() - t0) / 1000).toFixed(1).padStart(7);
  const tag = { debug: 'DBG', info: 'INF', warn: 'WRN', error: 'ERR' }[level];
  console.log(`[${el}s] ${tag} ${msg}`);
}

export const logger = {
  debug: (m: string) => emit('debug', m),
  info: (m: string) => emit('info', m),
  warn: (m: string) => emit('warn', m),
  error: (m: string) => emit('error', m),
};
