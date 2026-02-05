import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from './components/Layout/Layout'
import { ErrorBoundary } from './components/ErrorBoundary'
import { Traffic } from './pages/Traffic'
import { RoutesPage } from './pages/Routes'
import { Cache } from './pages/Cache'
import { VPN } from './pages/VPN'
import { Settings } from './pages/Settings'
import { Logs } from './pages/Logs'

export default function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Navigate to="/traffic" replace />} />
            <Route path="traffic" element={<Traffic />} />
            <Route path="routes" element={<RoutesPage />} />
            <Route path="cache" element={<Cache />} />
            <Route path="vpn" element={<VPN />} />
            <Route path="settings" element={<Settings />} />
            <Route path="logs" element={<Logs />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ErrorBoundary>
  )
}
