import { useCallback, useEffect, useRef } from 'react'

// useModalA11y bundles the dialog behavior Config/Modal.tsx established:
// Escape closes, Tab is trapped inside the dialog, the first focusable
// element receives focus on open, focus returns to the opener on close,
// and body scrolling is locked while open. Attach the returned ref to the
// dialog panel (the element with role="dialog").
export function useModalA11y(isOpen: boolean, onClose: () => void) {
  const modalRef = useRef<HTMLDivElement>(null)
  const previousActiveElement = useRef<HTMLElement | null>(null)

  const getFocusableElements = useCallback(() => {
    if (!modalRef.current) return []
    return Array.from(
      modalRef.current.querySelectorAll<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      )
    ).filter((el) => !el.hasAttribute('disabled'))
  }, [])

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose()
        return
      }

      if (e.key === 'Tab') {
        const focusableElements = getFocusableElements()
        if (focusableElements.length === 0) return

        const firstElement = focusableElements[0]
        const lastElement = focusableElements[focusableElements.length - 1]

        if (e.shiftKey) {
          if (document.activeElement === firstElement) {
            e.preventDefault()
            lastElement.focus()
          }
        } else {
          if (document.activeElement === lastElement) {
            e.preventDefault()
            firstElement.focus()
          }
        }
      }
    },
    [onClose, getFocusableElements]
  )

  useEffect(() => {
    if (isOpen) {
      previousActiveElement.current = document.activeElement as HTMLElement

      document.addEventListener('keydown', handleKeyDown)
      document.body.style.overflow = 'hidden'

      requestAnimationFrame(() => {
        const focusableElements = getFocusableElements()
        if (focusableElements.length > 0) {
          focusableElements[0].focus()
        }
      })
    }
    return () => {
      document.removeEventListener('keydown', handleKeyDown)
      document.body.style.overflow = ''

      if (previousActiveElement.current) {
        previousActiveElement.current.focus()
      }
    }
  }, [isOpen, handleKeyDown, getFocusableElements])

  return modalRef
}
