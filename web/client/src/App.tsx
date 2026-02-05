import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from './components/Layout/Layout'
import { ErrorBoundary, SectionErrorBoundary } from './components/ErrorBoundary'
import { Traffic } from './pages/Traffic'
import { RoutesPage } from './pages/Routes'
import { Cache } from './pages/Cache'
import { VPN } from './pages/VPN'
import { Mesh } from './pages/Mesh'
import { Settings } from './pages/Settings'
import { Logs } from './pages/Logs'

export default function App() {
  return (
    <ErrorBoundary section="Application">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Navigate to="/traffic" replace />} />
            <Route path="traffic" element={
              <SectionErrorBoundary section="Traffic">
                <Traffic />
              </SectionErrorBoundary>
            } />
            <Route path="routes" element={
              <SectionErrorBoundary section="Routes">
                <RoutesPage />
              </SectionErrorBoundary>
            } />
            <Route path="cache" element={
              <SectionErrorBoundary section="Cache">
                <Cache />
              </SectionErrorBoundary>
            } />
            <Route path="vpn" element={
              <SectionErrorBoundary section="VPN">
                <VPN />
              </SectionErrorBoundary>
            } />
            <Route path="mesh" element={
              <SectionErrorBoundary section="Mesh">
                <Mesh />
              </SectionErrorBoundary>
            } />
            <Route path="settings" element={
              <SectionErrorBoundary section="Settings">
                <Settings />
              </SectionErrorBoundary>
            } />
            <Route path="logs" element={
              <SectionErrorBoundary section="Logs">
                <Logs />
              </SectionErrorBoundary>
            } />
          </Route>
        </Routes>
      </BrowserRouter>
    </ErrorBoundary>
  )
}
