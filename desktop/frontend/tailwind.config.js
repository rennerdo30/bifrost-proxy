/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bifrost: {
          bg: '#0a0e17',
          card: '#111827',
          border: '#1f2937',
          accent: '#3b82f6',
          'accent-hover': '#2563eb',
          success: '#22c55e',
          warning: '#f59e0b',
          error: '#ef4444',
          text: '#f9fafb',
          'text-muted': '#9ca3af',
        }
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'spin-slow': 'spin 2s linear infinite',
      }
    },
  },
  plugins: [],
}
