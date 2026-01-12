import { Outlet } from 'react-router-dom'
import { Header } from './Header'
import { TabNav } from './TabNav'

export function Layout() {
  return (
    <div className="min-h-screen bg-bifrost-bg">
      <Header />
      <main className="max-w-7xl mx-auto px-6 py-6">
        <div className="mb-6">
          <TabNav />
        </div>
        <Outlet />
      </main>
    </div>
  )
}
