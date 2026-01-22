import { useState } from 'react';
import { ServerInfo } from '../hooks/useClient';

interface ServerSelectorProps {
  servers: ServerInfo[];
  currentServer: string;
  onSelect: (name: string) => void;
  disabled?: boolean;
}

export function ServerSelector({ servers, currentServer, onSelect, disabled }: ServerSelectorProps) {
  const [isOpen, setIsOpen] = useState(false);

  const selectedServer = servers.find(s => s.name === currentServer) || servers[0];

  if (servers.length === 0) {
    return (
      <div className="card">
        <p className="text-sm text-bifrost-text-muted text-center">No servers configured</p>
      </div>
    );
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': return 'bg-bifrost-success';
      case 'offline': return 'bg-bifrost-error';
      default: return 'bg-bifrost-warning';
    }
  };

  return (
    <div className="relative">
      <button
        onClick={() => !disabled && setIsOpen(!isOpen)}
        disabled={disabled}
        className={`w-full card flex items-center justify-between transition-colors ${
          disabled ? 'opacity-50 cursor-not-allowed' : 'hover:border-bifrost-accent cursor-pointer'
        }`}
      >
        <div className="flex items-center gap-3">
          <span className={`w-2 h-2 rounded-full ${getStatusColor(selectedServer?.status || 'unknown')}`} />
          <div className="text-left">
            <p className="text-sm font-medium text-bifrost-text">{selectedServer?.name || 'Select Server'}</p>
            <p className="text-xs text-bifrost-text-muted">{selectedServer?.address}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {selectedServer?.latency_ms && (
            <span className="text-xs text-bifrost-text-muted">{selectedServer.latency_ms}ms</span>
          )}
          <svg className={`w-4 h-4 text-bifrost-text-muted transition-transform ${isOpen ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>

      {/* Dropdown */}
      {isOpen && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 z-10"
            onClick={() => setIsOpen(false)}
          />

          {/* Menu */}
          <div className="absolute z-20 w-full mt-2 bg-bifrost-card border border-bifrost-border rounded-xl shadow-xl overflow-hidden">
            {servers.map((server) => (
              <button
                key={server.name}
                onClick={() => {
                  onSelect(server.name);
                  setIsOpen(false);
                }}
                disabled={server.status === 'offline'}
                className={`w-full px-4 py-3 flex items-center justify-between transition-colors ${
                  server.name === currentServer
                    ? 'bg-bifrost-accent/10 border-l-2 border-bifrost-accent'
                    : 'hover:bg-bifrost-border/50'
                } ${server.status === 'offline' ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}`}
              >
                <div className="flex items-center gap-3">
                  <span className={`w-2 h-2 rounded-full ${getStatusColor(server.status)}`} />
                  <div className="text-left">
                    <p className="text-sm font-medium text-bifrost-text">{server.name}</p>
                    <p className="text-xs text-bifrost-text-muted">{server.address}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {server.latency_ms && (
                    <span className="text-xs text-bifrost-text-muted">{server.latency_ms}ms</span>
                  )}
                  {server.is_default && (
                    <span className="text-xs px-1.5 py-0.5 bg-bifrost-accent/20 text-bifrost-accent rounded">
                      Default
                    </span>
                  )}
                  {server.name === currentServer && (
                    <svg className="w-4 h-4 text-bifrost-success" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                    </svg>
                  )}
                </div>
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
