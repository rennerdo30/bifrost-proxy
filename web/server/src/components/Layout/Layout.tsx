import type { MouseEvent } from 'react'
import { Outlet } from 'react-router-dom'
import { Header } from './Header'
import { TabNav } from './TabNav'

/** Target of the skip link; also used as the <main> element id. */
const MAIN_CONTENT_ID = 'main-content'

export function Layout() {
  // The skip link must move focus itself instead of letting the browser
  // navigate to "#main-content": the app runs under a HashRouter, so the
  // fragment IS the route. Letting the default action through rewrites the
  // route to "main-content", which matches nothing and renders a blank page.
  // <main> carries tabIndex={-1} so it can receive focus programmatically.
  const handleSkip = (event: MouseEvent<HTMLAnchorElement>) => {
    event.preventDefault()
    const main = document.getElementById(MAIN_CONTENT_ID)
    if (!main) return
    main.focus()
    main.scrollIntoView()
  }

  return (
    <div className="relative min-h-screen bg-bifrost-bg">
      <a href={`#${MAIN_CONTENT_ID}`} className="skip-link" onClick={handleSkip}>
        Skip to main content
      </a>
      <Header />
      <TabNav />
      <main
        id={MAIN_CONTENT_ID}
        tabIndex={-1}
        className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:px-8"
      >
        <Outlet />
      </main>
    </div>
  )
}
