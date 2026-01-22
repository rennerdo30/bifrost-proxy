import { StatusResponse, formatBytes } from '../hooks/useClient';

interface StatusIndicatorProps {
  status: StatusResponse | null;
}

export function StatusIndicator({ status }: StatusIndicatorProps) {
  if (!status) {
    return (
      <div className="card text-center">
        <p className="text-bifrost-text-muted">Loading status...</p>
      </div>
    );
  }

  const isOnline = status.status !== 'offline';

  return (
    <div className="card space-y-3">
      {/* Server info */}
      <div className="flex items-center justify-between">
        <span className="text-sm text-bifrost-text-muted">Server</span>
        <span className="text-sm font-medium text-bifrost-text truncate max-w-[180px]">
          {status.server_address || 'Not configured'}
        </span>
      </div>

      {/* Proxy addresses */}
      {isOnline && (
        <>
          <div className="flex items-center justify-between">
            <span className="text-sm text-bifrost-text-muted">HTTP Proxy</span>
            <span className="text-sm font-mono text-bifrost-text">{status.http_proxy}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-sm text-bifrost-text-muted">SOCKS5 Proxy</span>
            <span className="text-sm font-mono text-bifrost-text">{status.socks5_proxy}</span>
          </div>
        </>
      )}

      {/* VPN Status */}
      <div className="flex items-center justify-between">
        <span className="text-sm text-bifrost-text-muted">VPN Mode</span>
        <span className={`text-sm font-medium ${status.vpn_enabled ? 'text-bifrost-success' : 'text-bifrost-text-muted'}`}>
          {status.vpn_enabled ? 'Enabled' : 'Disabled'}
        </span>
      </div>

      {/* Data transfer */}
      {isOnline && status.server_connected && (
        <div className="pt-2 border-t border-bifrost-border">
          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-1">
              <svg className="w-3 h-3 text-bifrost-success" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 11l5-5m0 0l5 5m-5-5v12" />
              </svg>
              <span className="text-bifrost-text-muted">{formatBytes(status.bytes_sent)}</span>
            </div>
            <div className="flex items-center gap-1">
              <svg className="w-3 h-3 text-bifrost-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M17 13l-5 5m0 0l-5-5m5 5V6" />
              </svg>
              <span className="text-bifrost-text-muted">{formatBytes(status.bytes_received)}</span>
            </div>
            <div className="flex items-center gap-1">
              <svg className="w-3 h-3 text-bifrost-warning" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
              <span className="text-bifrost-text-muted">{status.active_connections} active</span>
            </div>
          </div>
        </div>
      )}

      {/* Error message */}
      {status.last_error && (
        <div className="pt-2 border-t border-bifrost-border">
          <p className="text-xs text-bifrost-error truncate" title={status.last_error}>
            {status.last_error}
          </p>
        </div>
      )}
    </div>
  );
}
