export const usd = (n: number | null | undefined) => {
  if (n == null) return '—';
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(1)}K`;
  return `$${n.toFixed(2)}`;
};

export const pct = (n: number | null | undefined) =>
  n == null ? '—' : `${(n * 100).toFixed(1)}%`;

export const shortAddr = (a: string) => `${a.slice(0, 6)}…${a.slice(-4)}`;

export const ago = (d: Date | string | null) => {
  if (!d) return '—';
  const t = typeof d === 'string' ? new Date(d) : d;
  const years = (Date.now() - t.getTime()) / 31_557_600_000;
  return years >= 1 ? `${years.toFixed(1)}y ago` : `${Math.round(years * 12)}mo ago`;
};

export const etherscan = (a: string, kind: 'address' | 'tx' = 'address') =>
  `https://etherscan.io/${kind}/${a}`;
