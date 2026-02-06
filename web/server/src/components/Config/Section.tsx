import { useState, useRef, useEffect, ReactNode } from 'react'

interface SectionProps {
  title: string
  badge?: 'hot-reload' | 'restart-required'
  defaultOpen?: boolean
  id?: string
  icon?: ReactNode
  description?: string
  children: ReactNode
}

export function Section({ title, badge, defaultOpen = false, id, icon, description, children }: SectionProps) {
  const [isOpen, setIsOpen] = useState(defaultOpen)
  const contentRef = useRef<HTMLDivElement>(null)
  const [contentHeight, setContentHeight] = useState<number | undefined>(undefined)
  const sectionId = id || `section-${title.toLowerCase().replace(/\s+/g, '-')}`

  useEffect(() => {
    if (contentRef.current) {
      setContentHeight(contentRef.current.scrollHeight)
    }
  }, [isOpen, children])

  return (
    <div className="card-section" id={sectionId}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="card-section-header w-full flex items-center justify-between text-left"
        aria-expanded={isOpen}
        aria-controls={`${sectionId}-content`}
        aria-label={`${isOpen ? 'Collapse' : 'Expand'} ${title} section`}
      >
        <div className="flex items-center gap-3">
          {icon ? (
            <span className="text-bifrost-accent">{icon}</span>
          ) : (
            <svg
              className={`w-5 h-5 text-bifrost-muted transition-transform duration-200 ${isOpen ? 'rotate-90' : ''}`}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              aria-hidden="true"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
            </svg>
          )}
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-lg font-semibold text-white">{title}</h3>
              {badge && (
                <span className={`badge ${badge === 'hot-reload' ? 'badge-success' : 'badge-warning'}`}>
                  {badge === 'hot-reload' ? 'Hot Reload' : 'Restart Required'}
                </span>
              )}
            </div>
            {description && (
              <p className="text-sm text-bifrost-muted mt-0.5">{description}</p>
            )}
          </div>
        </div>
        {icon && (
          <svg
            className={`w-5 h-5 text-bifrost-muted transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            aria-hidden="true"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        )}
      </button>
      <div
        id={`${sectionId}-content`}
        ref={contentRef}
        className="overflow-hidden transition-all duration-300 ease-in-out"
        style={{
          maxHeight: isOpen ? (contentHeight ? `${contentHeight + 32}px` : '9999px') : '0px',
          opacity: isOpen ? 1 : 0,
        }}
      >
        <div className="card-section-body">{children}</div>
      </div>
    </div>
  )
}
