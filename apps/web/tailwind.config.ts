import type { Config } from 'tailwindcss';
export default {
  content: ['./src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        base:    '#0a0b0d',
        panel:   '#121417',
        edge:    '#1e2228',
        muted:   '#7d8590',
        ink:     '#e6edf3',
        accent:  '#4a9eff',
        good:    '#3fb950',
        warn:    '#d29922',
        bad:     '#f85149',
      },
      fontFamily: { mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'] },
    },
  },
  plugins: [],
} satisfies Config;
