import { useEffect, useCallback } from 'react'
import { useBlocker } from 'react-router-dom'

/**
 * Hook that warns users about unsaved changes when navigating away.
 * Uses both browser beforeunload and react-router blocker.
 */
export function useUnsavedChanges(hasChanges: boolean) {
  // Browser tab/window close warning
  useEffect(() => {
    if (!hasChanges) return

    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault()
    }

    window.addEventListener('beforeunload', handler)
    return () => window.removeEventListener('beforeunload', handler)
  }, [hasChanges])

  // React Router navigation blocking
  const blocker = useBlocker(
    useCallback(
      () => hasChanges,
      [hasChanges]
    )
  )

  return { blocker }
}
