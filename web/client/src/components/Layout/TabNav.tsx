import { NavLink } from 'react-router-dom'

const tabs = [
  { path: '/traffic', label: 'Traffic', icon: 'M13 10V3L4 14h7v7l9-11h-7z' },
  { path: '/routes', label: 'Routes', icon: 'M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7' },
]

export function TabNav() {
  return (
    <nav className="flex gap-2 p-1 bg-bifrost-card rounded-xl border border-bifrost-border">
      {tabs.map((tab) => (
        <NavLink
          key={tab.path}
          to={tab.path}
          className={({ isActive }) =>
            `tab flex items-center gap-2 ${isActive ? 'tab-active' : 'tab-inactive'}`
          }
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={tab.icon} />
          </svg>
          {tab.label}
        </NavLink>
      ))}
    </nav>
  )
}
