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
        // Palette is driven by CSS custom properties so the whole UI can be
        // re-themed (dark <-> light) without duplicating utility classes.
        // Values live in src/index.css (:root and html.light).
        bifrost: {
          bg: 'var(--bifrost-bg)',
          'bg-elevated': 'var(--bifrost-bg-elevated)',
          card: 'var(--bifrost-card)',
          'card-hover': 'var(--bifrost-card-hover)',
          'card-active': 'var(--bifrost-card-active)',
          border: 'var(--bifrost-border)',
          'border-subtle': 'var(--bifrost-border-subtle)',
          accent: 'var(--bifrost-accent)',
          'accent-hover': 'var(--bifrost-accent-hover)',
          'accent-glow': 'var(--bifrost-accent-glow)',
          success: 'var(--bifrost-success)',
          warning: 'var(--bifrost-warning)',
          error: 'var(--bifrost-error)',
          heading: 'var(--bifrost-heading)',
          text: 'var(--bifrost-text)',
          subtle: 'var(--bifrost-subtle)',
          muted: 'var(--bifrost-muted)',
          'on-accent': 'var(--bifrost-on-accent)',
          'on-warning': 'var(--bifrost-on-warning)',
          'on-success': 'var(--bifrost-on-success)',
          overlay: 'var(--bifrost-overlay)',
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
