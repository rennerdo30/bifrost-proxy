import { Outlet } from 'react-router-dom'
import { Header } from './Header'
import { TabNav } from './TabNav'

/** Anchor target of the skip link; also used as the <main> element id. */
const MAIN_CONTENT_ID = 'main-content'

export function Layout() {
  return (
    <div className="relative min-h-screen bg-bifrost-bg">
      <a href={`#${MAIN_CONTENT_ID}`} className="skip-link">
        Skip to main content
      </a>
      <Header />
      <main
        id={MAIN_CONTENT_ID}
        className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:px-8"
      >
        <div className="mb-6">
          <TabNav />
        </div>
        <Outlet />
      </main>
    </div>
  )
}
