import type { Config } from 'tailwindcss';

const config: Config = {
  darkMode: ['class'],
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}', './lib/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#0a0a0f',
        card: '#13131a',
        border: '#1e1e2e',
        accent: '#6366f1',
        accentHover: '#4f46e5',
        text: '#e2e8f0',
        textSecondary: '#94a3b8',
        muted: '#475569',
        critical: '#ef4444',
        high: '#f97316',
        medium: '#eab308',
        low: '#22c55e',
        info: '#3b82f6'
      }
    }
  },
  plugins: []
};

export default config;
