import { useClient } from './hooks/useClient';
import { ConnectButton } from './components/ConnectButton';
import { StatusIndicator } from './components/StatusIndicator';
import { ServerSelector } from './components/ServerSelector';
import { QuickSettings } from './components/QuickSettings';

function App() {
  const {
    status,
    servers,
    settings,
    proxySettings,
    connectionStatus,
    error,
    loading,
    restarting,
    connect,
    disconnect,
    selectServer,
    updateSettings,
    updateProxySettings,
    restartClient,
    toggleVPN,
    openDashboard,
    quit,
    clearError,
  } = useClient();

  return (
    <div className="h-full flex flex-col bg-bifrost-bg">
      {/* macOS title bar safe area */}
      <div className="h-7 flex-shrink-0 macos-drag-region" style={{ minHeight: '28px' }} />

      {/* Header - draggable for window movement */}
      <header className="flex items-center justify-between px-4 py-3 border-b border-bifrost-border macos-drag-region">
        <div className="flex items-center gap-2">
          <svg className="w-6 h-6 text-bifrost-accent" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <h1 className="text-base font-semibold text-bifrost-text">Bifrost</h1>
        </div>
        <div className="flex items-center gap-1 macos-no-drag">
          <a
            href="https://github.com/rennerdo30/bifrost-proxy"
            target="_blank"
            rel="noopener noreferrer"
            className="p-2 text-bifrost-text-muted hover:text-bifrost-text hover:bg-bifrost-border/50 rounded-lg transition-colors"
            title="GitHub Repository"
            aria-label="View source on GitHub"
          >
            <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.17 6.839 9.49.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.604-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.167 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
            </svg>
          </a>
          <button
            onClick={openDashboard}
            className="p-2 text-bifrost-text-muted hover:text-bifrost-text hover:bg-bifrost-border/50 rounded-lg transition-colors"
            title="Open Dashboard"
            aria-label="Open dashboard"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
            </svg>
          </button>
          <button
            onClick={quit}
            className="p-2 text-bifrost-text-muted hover:text-bifrost-error hover:bg-bifrost-border/50 rounded-lg transition-colors"
            title="Quit"
            aria-label="Close application"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      </header>

      {/* Error Banner */}
      {error && (
        <div className="mx-4 mt-4 px-4 py-3 bg-bifrost-error/10 border border-bifrost-error/30 rounded-lg flex items-center justify-between">
          <p className="text-sm text-bifrost-error">{error}</p>
          <button
            onClick={clearError}
            className="text-bifrost-error hover:text-red-400"
            aria-label="Dismiss error"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      {/* Main Content */}
      <main className="flex-1 overflow-y-auto px-4 py-4 space-y-4 macos-no-drag">
        {/* Connect Button */}
        <div className="flex justify-center py-4">
          <ConnectButton
            status={connectionStatus}
            loading={loading}
            onConnect={connect}
            onDisconnect={disconnect}
          />
        </div>

        {/* Server Selector */}
        <ServerSelector
          servers={servers}
          currentServer={settings?.current_server || ''}
          onSelect={selectServer}
          disabled={connectionStatus === 'connecting' || loading}
          onAddServer={openDashboard}
        />

        {/* Status */}
        <StatusIndicator status={status} />

        {/* Quick Settings */}
        <QuickSettings
          settings={settings}
          proxySettings={proxySettings}
          onUpdate={updateSettings}
          onUpdateProxy={updateProxySettings}
          onRestart={restartClient}
          vpnEnabled={status?.vpn_enabled || false}
          onToggleVPN={toggleVPN}
          restarting={restarting}
        />
      </main>

      {/* Footer */}
      <footer className="px-4 py-2 border-t border-bifrost-border flex-shrink-0 macos-no-drag">
        <div className="flex items-center justify-between text-xs text-bifrost-text-muted">
          <span>v{status?.version || '...'}</span>
          <button
            onClick={openDashboard}
            className="hover:text-bifrost-accent transition-colors"
          >
            Open full dashboard
          </button>
        </div>
      </footer>
    </div>
  );
}

export default App;
