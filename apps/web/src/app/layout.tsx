import './globals.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'liquidity archaeologist',
  description: 'Pre-2024 Ethereum token launches with surviving locked liquidity.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-base text-ink">{children}</body>
    </html>
  );
}
