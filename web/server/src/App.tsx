import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from './components/Layout/Layout'
import { ErrorBoundary } from './components/ErrorBoundary'
import { Dashboard } from './pages/Dashboard'
import { Backends } from './pages/Backends'
import { RequestLog } from './pages/RequestLog'
import { Clients } from './pages/Clients'
import { Cache } from './pages/Cache'
import { Mesh } from './pages/Mesh'
import { Config } from './pages/Config'
import { ConfigGenerator } from './pages/ConfigGenerator'
import { SetupGuide } from './pages/SetupGuide'

export default function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="backends" element={<Backends />} />
            <Route path="requests" element={<RequestLog />} />
            <Route path="clients" element={<Clients />} />
            <Route path="cache" element={<Cache />} />
            <Route path="mesh" element={<Mesh />} />
            <Route path="config" element={<Config />} />
            <Route path="generator" element={<ConfigGenerator />} />
            <Route path="setup" element={<SetupGuide />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ErrorBoundary>
  )
}
