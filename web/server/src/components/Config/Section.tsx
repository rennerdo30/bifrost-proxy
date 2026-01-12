import { useState, ReactNode } from 'react'

interface SectionProps {
  title: string
  badge?: 'hot-reload' | 'restart-required'
  defaultOpen?: boolean
  children: ReactNode
}

export function Section({ title, badge, defaultOpen = true, children }: SectionProps) {
  const [isOpen, setIsOpen] = useState(defaultOpen)

  return (
    <div className="card">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between text-left"
      >
        <div className="flex items-center gap-3">
          <svg
            className={`w-5 h-5 text-bifrost-muted transition-transform ${isOpen ? 'rotate-90' : ''}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
          </svg>
          <h3 className="text-lg font-semibold text-white">{title}</h3>
        </div>
        {badge && (
          <span className={`badge ${badge === 'hot-reload' ? 'badge-success' : 'badge-warning'}`}>
            {badge === 'hot-reload' ? 'Hot Reload' : 'Restart Required'}
          </span>
        )}
      </button>
      {isOpen && <div className="mt-4 pt-4 border-t border-bifrost-border">{children}</div>}
    </div>
  )
}
