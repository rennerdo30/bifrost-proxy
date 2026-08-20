import { useEffect } from 'react'

/**
 * Warns the user about unsaved changes before the tab is closed or reloaded.
 *
 * Note: react-router's `useBlocker` cannot be used here. It only works inside a
 * data router, while the app is mounted with `<HashRouter>`, so calling it threw
 * ("useBlocker must be used within a data router") and took the whole page down
 * via the error boundary.
 */
export function useUnsavedChanges(hasChanges: boolean) {
  useEffect(() => {
    if (!hasChanges) return

    const handler = (event: BeforeUnloadEvent) => {
      // Required for the browser to show its native confirmation dialog.
      event.preventDefault()
    }

    window.addEventListener('beforeunload', handler)
    return () => window.removeEventListener('beforeunload', handler)
  }, [hasChanges])
}
