import { ReactNode } from 'react'
import toast, { Toaster, Renderable } from 'react-hot-toast'

type ToastType = 'success' | 'error' | 'warning' | 'info'

interface ToastContextType {
  showToast: (message: string, type?: ToastType) => void
}

// Custom toast styling to match bifrost theme
const toastOptions = {
  duration: 5000,
  style: {
    background: 'rgb(30 41 59)', // bifrost-card
    color: 'rgb(248 250 252)', // bifrost-text
    border: '1px solid rgb(51 65 85)', // bifrost-border
    borderRadius: '0.5rem',
    padding: '0.75rem 1rem',
    fontSize: '0.875rem',
    maxWidth: '28rem',
    minWidth: '18.75rem',
  },
}

const iconStyles = 'w-5 h-5 flex-shrink-0'

const icons: Record<ToastType, Renderable> = {
  success: (
    <svg className={`${iconStyles} text-emerald-400`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
    </svg>
  ),
  error: (
    <svg className={`${iconStyles} text-red-400`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
    </svg>
  ),
  warning: (
    <svg className={`${iconStyles} text-amber-400`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
    </svg>
  ),
  info: (
    <svg className={`${iconStyles} text-cyan-400`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  ),
}

function showToast(message: string, type: ToastType = 'info') {
  const icon = icons[type]

  switch (type) {
    case 'success':
      toast.success(message, {
        ...toastOptions,
        icon,
        style: {
          ...toastOptions.style,
          borderColor: 'rgb(52 211 153)', // emerald-400
        },
      })
      break
    case 'error':
      toast.error(message, {
        ...toastOptions,
        icon,
        style: {
          ...toastOptions.style,
          borderColor: 'rgb(248 113 113)', // red-400
        },
      })
      break
    case 'warning':
      toast(message, {
        ...toastOptions,
        icon,
        style: {
          ...toastOptions.style,
          borderColor: 'rgb(251 191 36)', // amber-400
        },
      })
      break
    case 'info':
    default:
      toast(message, {
        ...toastOptions,
        icon,
        style: {
          ...toastOptions.style,
          borderColor: 'rgb(34 211 238)', // cyan-400
        },
      })
      break
  }
}

export function ToastProvider({ children }: { children: ReactNode }) {
  return (
    <>
      {children}
      <Toaster
        position="bottom-right"
        toastOptions={{
          className: 'backdrop-blur-sm',
        }}
      />
    </>
  )
}

export function useToast(): ToastContextType {
  return { showToast }
}

// Re-export toast for direct usage
export { toast }
