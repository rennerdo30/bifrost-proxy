import { useEffect } from 'react'

type ShortcutHandler = () => void

/**
 * Hook for registering keyboard shortcuts.
 * Supports mod+key combos where mod is Cmd on Mac, Ctrl elsewhere.
 *
 * @example
 * useKeyboardShortcuts({ 'mod+s': handleSave })
 */
export function useKeyboardShortcuts(shortcuts: Record<string, ShortcutHandler>) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const isMod = e.metaKey || e.ctrlKey

      for (const [combo, fn] of Object.entries(shortcuts)) {
        const parts = combo.toLowerCase().split('+')
        const key = parts[parts.length - 1]
        const needsMod = parts.includes('mod')

        if (needsMod && isMod && e.key.toLowerCase() === key) {
          e.preventDefault()
          fn()
          return
        }

        if (!needsMod && !isMod && e.key.toLowerCase() === key) {
          fn()
          return
        }
      }
    }

    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [shortcuts])
}
