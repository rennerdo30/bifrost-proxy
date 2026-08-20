import { useCallback, useEffect, useState } from 'react'

export type Theme = 'light' | 'dark'

/** localStorage key holding the user's explicit theme choice. */
export const THEME_STORAGE_KEY = 'bifrost-theme'

/** `content` of the <meta name="theme-color"> tag, per theme. */
const THEME_COLORS: Record<Theme, string> = {
  dark: '#0a0e17',
  light: '#f4f6f9',
}

const LIGHT_MEDIA_QUERY = '(prefers-color-scheme: light)'

function isTheme(value: unknown): value is Theme {
  return value === 'light' || value === 'dark'
}

/** Theme that should be used when the user has not chosen one explicitly. */
function systemTheme(): Theme {
  return window.matchMedia(LIGHT_MEDIA_QUERY).matches ? 'light' : 'dark'
}

function storedTheme(): Theme | null {
  try {
    const value = localStorage.getItem(THEME_STORAGE_KEY)
    return isTheme(value) ? value : null
  } catch {
    // Private browsing modes can throw on access; fall back to the OS setting.
    return null
  }
}

/**
 * Reads the theme that the inline bootstrap script in index.html already
 * applied, so the first render matches what is on screen (no flash).
 */
function currentTheme(): Theme {
  if (typeof document === 'undefined') return 'dark'
  if (document.documentElement.classList.contains('light')) return 'light'
  if (document.documentElement.classList.contains('dark')) return 'dark'
  return storedTheme() ?? systemTheme()
}

export function applyTheme(theme: Theme): void {
  const root = document.documentElement
  root.classList.toggle('dark', theme === 'dark')
  root.classList.toggle('light', theme === 'light')
  root.style.colorScheme = theme

  const meta = document.querySelector('meta[name="theme-color"]')
  if (meta) meta.setAttribute('content', THEME_COLORS[theme])
}

/**
 * Light/dark theme state persisted in localStorage. Without a stored choice the
 * OS preference is followed, including later changes to it.
 */
export function useTheme() {
  const [theme, setTheme] = useState<Theme>(currentTheme)

  useEffect(() => {
    applyTheme(theme)
  }, [theme])

  useEffect(() => {
    if (storedTheme() !== null) return
    const media = window.matchMedia(LIGHT_MEDIA_QUERY)
    const onChange = () => setTheme(systemTheme())
    media.addEventListener('change', onChange)
    return () => media.removeEventListener('change', onChange)
  }, [])

  const toggleTheme = useCallback(() => {
    setTheme((previous) => {
      const next: Theme = previous === 'dark' ? 'light' : 'dark'
      try {
        localStorage.setItem(THEME_STORAGE_KEY, next)
      } catch {
        // Persisting is best effort — the toggle still works for this session.
      }
      return next
    })
  }, [])

  return { theme, toggleTheme }
}
