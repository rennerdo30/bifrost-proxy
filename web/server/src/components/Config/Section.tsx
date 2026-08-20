import { useState, useRef, useEffect, ReactNode } from 'react'
import { useConfigSectionState } from './ConfigSectionContext'
import { getSectionMeta, type ConfigSectionKey } from './sectionMeta'

interface SectionProps {
  /**
   * The config section this panel edits. Drives the scroll-anchor id, the
   * hot-reload badge and the modified marker, so none of those can drift from
   * the server's own view of the section.
   */
  sectionKey: ConfigSectionKey
  /** Heading override; defaults to the title in sectionMeta. */
  title?: string
  icon?: ReactNode
  description?: string
  children: ReactNode
}

export function Section({ sectionKey, title, icon, description, children }: SectionProps) {
  const shared = useConfigSectionState()
  const sectionMeta = getSectionMeta(sectionKey)
  const heading = title ?? sectionMeta.title
  const sectionId = sectionMeta.domId
  const contentId = `${sectionId}-content`

  // Fall back to local state when rendered outside the editor's provider so the
  // component stays usable (and testable) standalone.
  const [localOpen, setLocalOpen] = useState(false)
  const isOpen = shared ? shared.openSections.has(sectionKey) : localOpen
  const setOpen = () => {
    if (shared) shared.toggleSection(sectionKey)
    else setLocalOpen((prev) => !prev)
  }

  const hotReloadable = shared ? shared.hotReloadable(sectionKey) : sectionMeta.hotReloadable
  const isDirty = shared?.dirtySections.has(sectionKey) ?? false

  const contentRef = useRef<HTMLDivElement>(null)
  const [contentHeight, setContentHeight] = useState<number | undefined>(undefined)

  useEffect(() => {
    if (contentRef.current) {
      setContentHeight(contentRef.current.scrollHeight)
    }
  }, [isOpen, children])

  return (
    <div
      className={`card-section ${isDirty ? 'ring-1 ring-bifrost-accent/40' : ''}`}
      id={sectionId}
      data-section-key={sectionKey}
    >
      <button
        onClick={setOpen}
        className="card-section-header w-full flex items-center justify-between gap-3 text-left"
        aria-expanded={isOpen}
        aria-controls={contentId}
      >
        <div className="flex items-center gap-3 min-w-0">
          {icon ? (
            <span className="text-bifrost-accent shrink-0" aria-hidden="true">{icon}</span>
          ) : (
            <svg
              className={`w-5 h-5 shrink-0 text-bifrost-muted transition-transform duration-200 ${isOpen ? 'rotate-90' : ''}`}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              aria-hidden="true"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
            </svg>
          )}
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-lg font-semibold text-bifrost-heading">{heading}</h3>
              <span
                className={`badge ${hotReloadable ? 'badge-success' : 'badge-warning'}`}
                title={
                  hotReloadable
                    ? 'Saving applies this section to the running server immediately'
                    : 'Saving writes this section to disk; it takes effect after a server restart'
                }
              >
                {hotReloadable ? 'Hot Reload' : 'Restart Required'}
              </span>
              {isDirty && (
                <span className="badge badge-info" data-testid={`dirty-${sectionKey}`}>
                  Modified
                </span>
              )}
            </div>
            {description && (
              <p className="text-sm text-bifrost-muted mt-0.5">{description}</p>
            )}
          </div>
        </div>
        <svg
          className={`w-5 h-5 shrink-0 text-bifrost-muted transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      <div
        id={contentId}
        ref={contentRef}
        // `inert` keeps a collapsed panel's inputs out of the tab order and out
        // of the accessibility tree while still allowing the height transition
        // (which `hidden`/`display:none` would cancel). Without it, keyboard and
        // screen-reader users walked through every field of all 17 collapsed
        // sections even though nothing was visible.
        inert={!isOpen}
        aria-hidden={!isOpen}
        className="overflow-hidden transition-all duration-300 ease-in-out"
        style={{
          maxHeight: isOpen ? (contentHeight ? `${contentHeight + 32}px` : 'none') : '0px',
          opacity: isOpen ? 1 : 0,
        }}
      >
        <div className="card-section-body">{children}</div>
      </div>
    </div>
  )
}
