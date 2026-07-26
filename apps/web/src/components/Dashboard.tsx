'use client';

/**
 * Main dashboard.
 *
 * The table is virtualized because a full result set is 40k+ rows and the
 * primary way people use this is to scroll and scan rather than to search — so
 * scrolling has to stay at 60fps with the whole set loaded.
 *
 * Filters are debounced and drive a keyset-paginated API rather than
 * client-side filtering, so the result count is bounded by the query, not by
 * how much we can hold in memory.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { usd, pct, shortAddr, ago, etherscan } from '@/lib/format';

export interface Row {
  address: string;
  kind: string;
  factory: string;
  dexName: string | null;
  token0: string;
  token1: string;
  createdBlock: number;
  createdAt: string | null;
  totalLiquidityUsd: number;
  lockedLiquidityUsd: number;
  burnedLiquidityUsd: number;
  lockedFraction: number;
  symbol0: string | null;
  symbol1: string | null;
  name0: string | null;
  name1: string | null;
}

const QUOTES = new Set(['WETH', 'USDC', 'USDT', 'DAI', 'FRAX', 'WBTC']);

/** The interesting token is whichever side isn't the quote asset. */
function subject(r: Row) {
  const s0 = r.symbol0 ?? '';
  const s1 = r.symbol1 ?? '';
  if (QUOTES.has(s0)) return { sym: s1 || shortAddr(r.token1), addr: r.token1, name: r.name1, quote: s0 };
  return { sym: s0 || shortAddr(r.token0), addr: r.token0, name: r.name0, quote: s1 };
}

interface Filters {
  minUsd: number;
  maxUsd: string;
  minLockedPct: number;
  lockType: string;
  kind: string;
  q: string;
}

const DEFAULTS: Filters = { minUsd: 100, maxUsd: '', minLockedPct: 0, lockType: '', kind: '', q: '' };

export default function Dashboard({ initialRows, stats }: { initialRows: Row[]; stats: Record<string, number> }) {
  const [filters, setFilters] = useState<Filters>(DEFAULTS);
  const [rows, setRows] = useState<Row[]>(initialRows);
  const [cursor, setCursor] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<Row | null>(null);
  const [live, setLive] = useState<Record<string, any>>(stats);
  const parentRef = useRef<HTMLDivElement>(null);
  const running = Boolean(live?.running);

  const qs = useMemo(() => {
    const p = new URLSearchParams();
    p.set('minUsd', String(filters.minUsd));
    if (filters.maxUsd) p.set('maxUsd', filters.maxUsd);
    if (filters.minLockedPct) p.set('minLockedPct', String(filters.minLockedPct));
    if (filters.lockType) p.set('lockType', filters.lockType);
    if (filters.kind) p.set('kind', filters.kind);
    if (filters.q) p.set('q', filters.q);
    return p.toString();
  }, [filters]);

  // Debounced refetch on filter change.
  useEffect(() => {
    const id = setTimeout(async () => {
      setLoading(true);
      const res = await fetch(`/api/tokens?${qs}`);
      const json = await res.json();
      setRows(json.rows);
      setCursor(json.nextCursor);
      setLoading(false);
      parentRef.current?.scrollTo({ top: 0 });
    }, 250);
    return () => clearTimeout(id);
  }, [qs]);

  const loadMore = useCallback(async () => {
    if (cursor == null || loading) return;
    setLoading(true);
    const res = await fetch(`/api/tokens?${qs}&cursor=${cursor}`);
    const json = await res.json();
    setRows((r) => [...r, ...json.rows]);
    setCursor(json.nextCursor);
    setLoading(false);
  }, [cursor, loading, qs]);

  const virt = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 52,
    overscan: 12,
  });

  // Infinite scroll: fetch the next page as the last rows come into view.
  useEffect(() => {
    const items = virt.getVirtualItems();
    if (items.length && items[items.length - 1].index >= rows.length - 15) loadMore();
  }, [virt.getVirtualItems(), rows.length, loadMore]);

  // --- Live updates ------------------------------------------------------
  // Poll the header stats every 4s so the pools/locked/scanned counters and
  // the "scanning" indicator move on their own.
  useEffect(() => {
    let active = true;
    const tick = async () => {
      try {
        const r = await fetch('/api/stats', { cache: 'no-store' });
        if (active && r.ok) setLive(await r.json());
      } catch {}
    };
    tick();
    const id = setInterval(tick, 4000);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, []);

  // While a scan is running, refresh the visible list every 5s (respecting the
  // current filters) so newly-found coins stream in without a manual reload.
  useEffect(() => {
    if (!running) return;
    const id = setInterval(async () => {
      try {
        const res = await fetch(`/api/tokens?${qs}`, { cache: 'no-store' });
        const json = await res.json();
        setRows(json.rows);
        setCursor(json.nextCursor);
      } catch {}
    }, 5000);
    return () => clearInterval(id);
  }, [running, qs]);

  return (
    <div className="flex h-screen flex-col">
      <Header stats={live} running={running} />
      <FilterBar filters={filters} setFilters={setFilters} count={rows.length} loading={loading} />

      <div className="grid grid-cols-[minmax(0,1fr)_auto] flex-1 overflow-hidden">
        <div className="flex flex-col overflow-hidden">
          <TableHead />
          <div ref={parentRef} className="flex-1 overflow-auto">
            <div style={{ height: virt.getTotalSize(), position: 'relative' }}>
              {virt.getVirtualItems().map((v) => {
                const r = rows[v.index];
                return (
                  <div
                    key={r.address}
                    onClick={() => setSelected(r)}
                    style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: v.size, transform: `translateY(${v.start}px)` }}
                    className={`grid cursor-pointer grid-cols-[3rem_minmax(0,2fr)_1fr_1fr_1fr_1fr_1fr] items-center gap-3 border-b border-edge px-4 text-sm hover:bg-panel ${
                      selected?.address === r.address ? 'bg-panel' : ''
                    }`}
                  >
                    <span className="tnum text-xs text-muted">{v.index + 1}</span>
                    <TokenCell row={r} />
                    <span className="tnum font-medium text-good">{usd(r.lockedLiquidityUsd)}</span>
                    <span className="tnum text-muted">{usd(r.totalLiquidityUsd)}</span>
                    <LockBar fraction={r.lockedFraction} />
                    <span className="tnum text-xs text-muted">{ago(r.createdAt)}</span>
                    <span className="text-xs uppercase text-muted">{r.dexName ?? r.kind}</span>
                  </div>
                );
              })}
            </div>
            {loading && <div className="p-4 text-center text-xs text-muted">loading…</div>}
            {!loading && rows.length === 0 && (
              <div className="p-12 text-center text-sm text-muted">
                No pools match these filters. Widen the range, or run a scan if the database is empty.
              </div>
            )}
          </div>
        </div>

        {selected && <DetailPanel row={selected} onClose={() => setSelected(null)} />}
      </div>
    </div>
  );
}

function Header({ stats, running }: { stats: Record<string, any>; running?: boolean }) {
  return (
    <header className="flex items-center justify-between border-b border-edge px-5 py-3">
      <div className="flex items-baseline gap-3">
        <h1 className="font-mono text-sm font-semibold tracking-tight">liquidity-archaeologist</h1>
        <span className="text-xs text-muted">pre-2024 ETH launches with surviving locked liquidity</span>
        {running && (
          <span className="flex items-center gap-1.5 rounded-full bg-good/15 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-good">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-good" />
            scanning live
          </span>
        )}
      </div>
      <div className="flex gap-6">
        <Stat label="pools" value={stats.passing?.toLocaleString() ?? '—'} />
        <Stat label="locked total" value={usd(stats.totalLocked)} />
        <Stat label="scanned" value={stats.discovered?.toLocaleString() ?? '—'} />
      </div>
    </header>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="text-right">
      <div className="tnum text-sm font-medium">{value}</div>
      <div className="text-[10px] uppercase tracking-wide text-muted">{label}</div>
    </div>
  );
}

function FilterBar({
  filters,
  setFilters,
  count,
  loading,
}: {
  filters: Filters;
  setFilters: (f: Filters) => void;
  count: number;
  loading: boolean;
}) {
  const set = <K extends keyof Filters>(k: K, v: Filters[K]) => setFilters({ ...filters, [k]: v });
  return (
    <div className="flex flex-wrap items-center gap-3 border-b border-edge bg-panel/50 px-5 py-2.5 text-xs">
      <input
        value={filters.q}
        onChange={(e) => set('q', e.target.value)}
        placeholder="symbol or address…"
        className="w-56 rounded border border-edge bg-base px-2.5 py-1.5 outline-none placeholder:text-muted focus:border-accent"
      />
      <label className="flex items-center gap-2 text-muted">
        min locked
        <input
          type="number"
          value={filters.minUsd}
          onChange={(e) => set('minUsd', Number(e.target.value) || 0)}
          className="tnum w-24 rounded border border-edge bg-base px-2 py-1.5 text-ink outline-none focus:border-accent"
        />
      </label>
      <label className="flex items-center gap-2 text-muted">
        max
        <input
          type="number"
          value={filters.maxUsd}
          placeholder="∞"
          onChange={(e) => set('maxUsd', e.target.value)}
          className="tnum w-24 rounded border border-edge bg-base px-2 py-1.5 text-ink outline-none focus:border-accent"
        />
      </label>
      <label className="flex items-center gap-2 text-muted">
        locked ≥ <span className="tnum w-8 text-ink">{filters.minLockedPct}%</span>
        <input
          type="range"
          min={0}
          max={100}
          value={filters.minLockedPct}
          onChange={(e) => set('minLockedPct', Number(e.target.value))}
          className="w-28 accent-[#4a9eff]"
        />
      </label>
      <select
        value={filters.lockType}
        onChange={(e) => set('lockType', e.target.value)}
        className="rounded border border-edge bg-base px-2 py-1.5 outline-none focus:border-accent"
      >
        <option value="">any lock type</option>
        <option value="burned">burned only (provable)</option>
        <option value="locked">locker-held</option>
      </select>
      <select
        value={filters.kind}
        onChange={(e) => set('kind', e.target.value)}
        className="rounded border border-edge bg-base px-2 py-1.5 outline-none focus:border-accent"
      >
        <option value="">all DEXes</option>
        <option value="v2">V2-style</option>
        <option value="v3">V3-style</option>
      </select>
      <span className="ml-auto tnum text-muted">
        {loading ? 'querying…' : `${count.toLocaleString()} loaded`}
      </span>
    </div>
  );
}

function TableHead() {
  const cols = ['#', 'token', 'locked usd', 'pool usd', 'locked %', 'launched', 'dex'];
  return (
    <div className="grid grid-cols-[3rem_minmax(0,2fr)_1fr_1fr_1fr_1fr_1fr] gap-3 border-b border-edge px-4 py-2 text-[10px] uppercase tracking-wide text-muted">
      {cols.map((c) => (
        <span key={c}>{c}</span>
      ))}
    </div>
  );
}

function TokenCell({ row }: { row: Row }) {
  const s = subject(row);
  return (
    <div className="min-w-0">
      <div className="truncate font-medium">
        {s.sym} <span className="text-muted">/ {s.quote}</span>
      </div>
      <div className="truncate font-mono text-[10px] text-muted">{s.addr}</div>
    </div>
  );
}

function LockBar({ fraction }: { fraction: number }) {
  const p = Math.min(Math.max(fraction, 0), 1);
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-14 overflow-hidden rounded-full bg-edge">
        <div className="h-full rounded-full bg-accent" style={{ width: `${p * 100}%` }} />
      </div>
      <span className="tnum text-xs text-muted">{pct(fraction)}</span>
    </div>
  );
}

function DetailPanel({ row, onClose }: { row: Row; onClose: () => void }) {
  const s = subject(row);
  const [holders, setHolders] = useState<any[] | null>(null);

  useEffect(() => {
    setHolders(null);
    fetch(`/api/tokens/${row.address}/holders`)
      .then((r) => (r.ok ? r.json() : { holders: [] }))
      .then((j) => setHolders(j.holders ?? []))
      .catch(() => setHolders([]));
  }, [row.address]);

  return (
    <aside className="w-[420px] overflow-y-auto border-l border-edge bg-panel">
      <div className="flex items-start justify-between border-b border-edge p-4">
        <div className="min-w-0">
          <div className="truncate text-base font-semibold">{s.sym}</div>
          <div className="truncate text-xs text-muted">{s.name ?? 'unnamed token'}</div>
        </div>
        <button onClick={onClose} className="rounded px-2 text-muted hover:text-ink" aria-label="Close">
          ✕
        </button>
      </div>

      <dl className="grid grid-cols-2 gap-px bg-edge">
        <Field label="Locked USD" value={usd(row.lockedLiquidityUsd)} tone="good" />
        <Field label="Burned USD" value={usd(row.burnedLiquidityUsd)} />
        <Field label="Pool total" value={usd(row.totalLiquidityUsd)} />
        <Field label="Locked share" value={pct(row.lockedFraction)} />
        <Field label="Launched" value={ago(row.createdAt)} />
        <Field label="Block" value={row.createdBlock.toLocaleString()} />
      </dl>

      <div className="space-y-3 p-4 text-xs">
        <LinkRow label="Token" addr={s.addr} />
        <LinkRow label="Pool" addr={row.address} />
        <LinkRow label="Factory" addr={row.factory} />
      </div>

      <div className="border-t border-edge p-4">
        <h3 className="mb-2 text-[10px] uppercase tracking-wide text-muted">LP holders</h3>
        {holders === null ? (
          <div className="text-xs text-muted">loading…</div>
        ) : holders.length === 0 ? (
          <div className="text-xs text-muted">No holder detail stored for this pool.</div>
        ) : (
          <ul className="space-y-1.5">
            {holders.map((h) => (
              <li key={h.holder} className="flex items-center justify-between gap-2 text-xs">
                <a
                  href={etherscan(h.holder)}
                  target="_blank"
                  rel="noreferrer"
                  className="truncate font-mono text-[10px] text-accent hover:underline"
                >
                  {shortAddr(h.holder)}
                </a>
                <span className={`shrink-0 rounded px-1.5 py-0.5 text-[9px] uppercase ${badge(h.classification)}`}>
                  {h.classification.replace(/_/g, ' ')}
                </span>
                <span className="tnum shrink-0 text-muted">{pct(h.fraction)}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </aside>
  );
}

const badge = (c: string) =>
  c === 'burned'
    ? 'bg-good/15 text-good'
    : c === 'locker_known'
      ? 'bg-accent/15 text-accent'
      : c === 'locker_unknown_contract'
        ? 'bg-warn/15 text-warn'
        : 'bg-bad/15 text-bad';

function Field({ label, value, tone }: { label: string; value: string; tone?: 'good' }) {
  return (
    <div className="bg-panel p-3">
      <div className="text-[10px] uppercase tracking-wide text-muted">{label}</div>
      <div className={`tnum text-sm font-medium ${tone === 'good' ? 'text-good' : ''}`}>{value}</div>
    </div>
  );
}

function LinkRow({ label, addr }: { label: string; addr: string }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-muted">{label}</span>
      <a href={etherscan(addr)} target="_blank" rel="noreferrer" className="font-mono text-[10px] text-accent hover:underline">
        {shortAddr(addr)} ↗
      </a>
    </div>
  );
}
