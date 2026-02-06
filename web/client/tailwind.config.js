/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        bifrost: {
          bg: '#0a0e17',
          'bg-elevated': '#0f1520',
          card: '#111827',
          'card-hover': '#1a2234',
          'card-active': '#1e293b',
          border: '#1f2937',
          'border-subtle': '#172033',
          accent: '#3b82f6',
          'accent-hover': '#2563eb',
          'accent-glow': 'rgba(59, 130, 246, 0.15)',
          success: '#22c55e',
          warning: '#f59e0b',
          error: '#ef4444',
          muted: '#6b7280',
          text: '#e5e7eb',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Menlo', 'Monaco', 'monospace'],
      },
      animation: {
        'fade-in': 'fadeIn 0.3s ease-out',
        'slide-up': 'slideUp 0.3s ease-out',
        'slide-down': 'slideDown 0.2s ease-out',
        'pulse-subtle': 'pulseSubtle 2s ease-in-out infinite',
        'toast-in': 'toastIn 0.2s ease-out forwards',
        'toast-out': 'toastOut 0.2s ease-in forwards',
        'accordion-down': 'accordionDown 0.3s ease-out',
        'accordion-up': 'accordionUp 0.2s ease-out',
        'sticky-enter': 'stickyEnter 0.3s ease-out',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideDown: {
          '0%': { opacity: '0', transform: 'translateY(-10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        pulseSubtle: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.7' },
        },
        toastIn: {
          '0%': { opacity: '0', transform: 'translateX(100%)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        toastOut: {
          '0%': { opacity: '1', transform: 'translateX(0)' },
          '100%': { opacity: '0', transform: 'translateX(100%)' },
        },
        accordionDown: {
          '0%': { maxHeight: '0', opacity: '0' },
          '100%': { maxHeight: 'var(--accordion-height, 1000px)', opacity: '1' },
        },
        accordionUp: {
          '0%': { maxHeight: 'var(--accordion-height, 1000px)', opacity: '1' },
          '100%': { maxHeight: '0', opacity: '0' },
        },
        stickyEnter: {
          '0%': { opacity: '0', transform: 'translateY(100%)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
}
