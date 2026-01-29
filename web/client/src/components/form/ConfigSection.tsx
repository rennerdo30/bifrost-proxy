import { useState, ReactNode } from 'react'

interface ConfigSectionProps {
  title: string
  icon?: ReactNode
  description?: string
  restartRequired?: boolean
  defaultOpen?: boolean
  children: ReactNode
}

export function ConfigSection({
  title,
  icon,
  description,
  restartRequired = false,
  defaultOpen = true,
  children,
}: ConfigSectionProps) {
  const [isOpen, setIsOpen] = useState(defaultOpen)

  return (
    <section className="card">
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between text-left"
        aria-label={isOpen ? `Collapse ${title} section` : `Expand ${title} section`}
        aria-expanded={isOpen}
      >
        <div className="flex items-center gap-3">
          {icon && (
            <span className="text-bifrost-accent">{icon}</span>
          )}
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-lg font-medium text-bifrost-text">{title}</h3>
              {restartRequired && (
                <span className="px-2 py-0.5 text-[10px] font-semibold uppercase bg-bifrost-warning/20 text-bifrost-warning rounded">
                  Restart Required
                </span>
              )}
            </div>
            {description && (
              <p className="text-sm text-bifrost-muted mt-0.5">{description}</p>
            )}
          </div>
        </div>
        <svg
          className={`w-5 h-5 text-bifrost-muted transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {isOpen && (
        <div className="mt-4 pt-4 border-t border-bifrost-border/50">
          {children}
        </div>
      )}
    </section>
  )
}
