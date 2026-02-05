import { createContext, useContext, useState, useCallback, useEffect, useRef, ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'

export type ToastType = 'success' | 'error' | 'warning' | 'info'

export interface ToastOptions {
  /** Duration in milliseconds before auto-dismiss. Default: 5000. Set to 0 to disable auto-dismiss. */
  duration?: number
  /** Toast type for styling */
  type?: ToastType
}

interface Toast {
  id: string
  message: string
  type: ToastType
  duration: number
  createdAt: number
}

interface ToastContextType {
  showToast: (message: string, typeOrOptions?: ToastType | ToastOptions) => void
  dismissToast: (id: string) => void
  dismissAll: () => void
}

const ToastContext = createContext<ToastContextType | null>(null)

const DEFAULT_DURATION = 5000
const MAX_VISIBLE_TOASTS = 5

let toastIdCounter = 0

function generateId(): string {
  return `toast-${Date.now()}-${toastIdCounter++}`
}

// Toast icons for each type
const ToastIcon = ({ type }: { type: ToastType }) => {
  const iconClass = 'w-5 h-5 flex-shrink-0'

  switch (type) {
    case 'success':
      return (
        <svg className={`${iconClass} text-emerald-400`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
        </svg>
      )
    case 'error':
      return (
        <svg className={`${iconClass} text-red-400`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
        </svg>
      )
    case 'warning':
      return (
        <svg className={`${iconClass} text-amber-400`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
      )
    case 'info':
    default:
      return (
        <svg className={`${iconClass} text-cyan-400`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      )
  }
}

// Get border color class based on toast type
function getBorderColor(type: ToastType): string {
  switch (type) {
    case 'success':
      return 'border-l-emerald-400'
    case 'error':
      return 'border-l-red-400'
    case 'warning':
      return 'border-l-amber-400'
    case 'info':
    default:
      return 'border-l-cyan-400'
  }
}

// Individual Toast component
function ToastItem({
  toast,
  onDismiss,
  isExiting
}: {
  toast: Toast
  onDismiss: () => void
  isExiting: boolean
}) {
  const [progress, setProgress] = useState(100)
  const startTimeRef = useRef(Date.now())
  const animationFrameRef = useRef<number | null>(null)

  useEffect(() => {
    if (toast.duration <= 0) return

    const updateProgress = () => {
      const elapsed = Date.now() - startTimeRef.current
      const remaining = Math.max(0, 100 - (elapsed / toast.duration) * 100)
      setProgress(remaining)

      if (remaining > 0) {
        animationFrameRef.current = requestAnimationFrame(updateProgress)
      }
    }

    animationFrameRef.current = requestAnimationFrame(updateProgress)

    return () => {
      if (animationFrameRef.current) {
        cancelAnimationFrame(animationFrameRef.current)
      }
    }
  }, [toast.duration])

  return (
    <div
      role="alert"
      aria-live="polite"
      className={`
        relative flex items-start gap-3
        bg-slate-800/95 backdrop-blur-sm
        border border-slate-700 border-l-4 ${getBorderColor(toast.type)}
        rounded-lg shadow-lg shadow-black/20
        p-4 pr-10 min-w-[300px] max-w-md
        ${isExiting ? 'animate-toast-out' : 'animate-toast-in'}
      `}
    >
      <ToastIcon type={toast.type} />
      <p className="text-sm text-slate-100 leading-relaxed break-words flex-1">
        {toast.message}
      </p>

      {/* Dismiss button */}
      <button
        onClick={onDismiss}
        className="absolute top-2 right-2 p-1.5 rounded-md text-slate-400 hover:text-slate-200 hover:bg-slate-700/50 transition-colors"
        aria-label="Dismiss notification"
      >
        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
        </svg>
      </button>

      {/* Progress bar for auto-dismiss */}
      {toast.duration > 0 && (
        <div className="absolute bottom-0 left-0 right-0 h-1 bg-slate-700/50 rounded-b-lg overflow-hidden">
          <div
            className={`h-full transition-none ${
              toast.type === 'success' ? 'bg-emerald-400/60' :
              toast.type === 'error' ? 'bg-red-400/60' :
              toast.type === 'warning' ? 'bg-amber-400/60' :
              'bg-cyan-400/60'
            }`}
            style={{ width: `${progress}%` }}
          />
        </div>
      )}
    </div>
  )
}

// Toast container that renders all toasts
function ToastContainer({
  toasts,
  onDismiss,
  exitingIds
}: {
  toasts: Toast[]
  onDismiss: (id: string) => void
  exitingIds: Set<string>
}) {
  if (toasts.length === 0) return null

  return (
    <div
      className="fixed bottom-4 right-4 z-50 flex flex-col-reverse gap-3"
      aria-label="Notifications"
    >
      {toasts.slice(0, MAX_VISIBLE_TOASTS).map((toast) => (
        <ToastItem
          key={toast.id}
          toast={toast}
          onDismiss={() => onDismiss(toast.id)}
          isExiting={exitingIds.has(toast.id)}
        />
      ))}
    </div>
  )
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const [exitingIds, setExitingIds] = useState<Set<string>>(new Set())
  const timersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map())

  // Fetch config to check notification preferences
  const { data: config } = useQuery({
    queryKey: ['config'],
    queryFn: api.getConfig,
    staleTime: 30000, // Cache for 30 seconds
  })

  // Check if notifications are enabled (defaults to true if not set)
  const notificationsEnabled = config?.tray?.show_notifications !== false

  const dismissToast = useCallback((id: string) => {
    // Start exit animation
    setExitingIds(prev => new Set(prev).add(id))

    // Clear any existing timer for this toast
    const timer = timersRef.current.get(id)
    if (timer) {
      clearTimeout(timer)
      timersRef.current.delete(id)
    }

    // Remove toast after animation completes
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id))
      setExitingIds(prev => {
        const next = new Set(prev)
        next.delete(id)
        return next
      })
    }, 200) // Match animation duration
  }, [])

  const dismissAll = useCallback(() => {
    toasts.forEach(toast => dismissToast(toast.id))
  }, [toasts, dismissToast])

  const showToast = useCallback((message: string, typeOrOptions?: ToastType | ToastOptions) => {
    // Don't show toast if notifications are disabled
    if (!notificationsEnabled) {
      return
    }

    let type: ToastType = 'info'
    let duration = DEFAULT_DURATION

    if (typeof typeOrOptions === 'string') {
      type = typeOrOptions
    } else if (typeOrOptions) {
      type = typeOrOptions.type ?? 'info'
      duration = typeOrOptions.duration ?? DEFAULT_DURATION
    }

    const id = generateId()
    const newToast: Toast = {
      id,
      message,
      type,
      duration,
      createdAt: Date.now(),
    }

    setToasts(prev => [newToast, ...prev])

    // Set up auto-dismiss timer if duration > 0
    if (duration > 0) {
      const timer = setTimeout(() => {
        dismissToast(id)
      }, duration)
      timersRef.current.set(id, timer)
    }
  }, [notificationsEnabled, dismissToast])

  // Clean up timers on unmount
  useEffect(() => {
    return () => {
      timersRef.current.forEach(timer => clearTimeout(timer))
      timersRef.current.clear()
    }
  }, [])

  return (
    <ToastContext.Provider value={{ showToast, dismissToast, dismissAll }}>
      {children}
      <ToastContainer
        toasts={toasts}
        onDismiss={dismissToast}
        exitingIds={exitingIds}
      />
    </ToastContext.Provider>
  )
}

export function useToast(): ToastContextType {
  const context = useContext(ToastContext)
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider')
  }
  return context
}
