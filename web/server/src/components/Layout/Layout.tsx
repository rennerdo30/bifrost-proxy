import { Outlet } from 'react-router-dom'
import { Header } from './Header'
import { TabNav } from './TabNav'

export function Layout() {
  return (
    <div className="min-h-screen bg-bifrost-bg">
      <Header />
      <TabNav />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <Outlet />
      </main>
    </div>
  )
}
