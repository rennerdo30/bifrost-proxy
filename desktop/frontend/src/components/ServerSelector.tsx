import { useState, useEffect, useCallback, useRef } from 'react';
import { ServerInfo } from '../hooks/useClient';
import { getStatusColor, getStatusLabel } from '../utils/status';

interface ServerSelectorProps {
  servers: ServerInfo[];
  currentServer: string;
  onSelect: (name: string) => void;
  disabled?: boolean;
  onAddServer?: () => void;
}

export function ServerSelector({ servers, currentServer, onSelect, disabled, onAddServer }: ServerSelectorProps) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown on Escape key
  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if (e.key === 'Escape' && isOpen) {
      setIsOpen(false);
    }
  }, [isOpen]);

  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  // Handle empty server list before accessing array elements
  if (!servers || servers.length === 0) {
    return (
      <div className="card text-center py-4">
        <p className="text-sm text-bifrost-text-muted mb-3">No servers configured</p>
        {onAddServer && (
          <button
            onClick={onAddServer}
            className="px-4 py-2 bg-bifrost-accent text-white rounded-lg hover:bg-bifrost-accent/80 transition-colors text-sm font-medium"
            aria-label="Add server"
          >
            Add Server
          </button>
        )}
      </div>
    );
  }

  // Handle edge case where selected server was removed - fall back to first available server
  const selectedServer = servers.find(s => s.name === currentServer) || servers[0];

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => !disabled && setIsOpen(!isOpen)}
        disabled={disabled}
        className={`w-full card flex items-center justify-between transition-colors ${
          disabled ? 'opacity-50 cursor-not-allowed' : 'hover:border-bifrost-accent cursor-pointer'
        }`}
        aria-haspopup="listbox"
        aria-expanded={isOpen}
        aria-label={`Select server, current: ${selectedServer?.name || 'None'}`}
      >
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className={`w-2 h-2 rounded-full ${getStatusColor(selectedServer?.status || 'unknown')}`} aria-hidden="true" />
            <span className="text-[10px] text-bifrost-text-muted uppercase">
              {getStatusLabel(selectedServer?.status || 'unknown')}
            </span>
          </div>
          <div className="text-left">
            <p className="text-sm font-medium text-bifrost-text">{selectedServer?.name || 'Select Server'}</p>
            <p className="text-xs text-bifrost-text-muted">{selectedServer?.address}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {selectedServer?.latency_ms && (
            <span className="text-xs text-bifrost-text-muted">{selectedServer.latency_ms}ms</span>
          )}
          <svg className={`w-4 h-4 text-bifrost-text-muted transition-transform ${isOpen ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
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
            aria-hidden="true"
          />

          {/* Menu */}
          <div
            className="absolute z-20 w-full mt-2 bg-bifrost-card border border-bifrost-border rounded-xl shadow-xl overflow-hidden"
            role="listbox"
            aria-label="Server list"
          >
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
                role="option"
                aria-selected={server.name === currentServer}
                aria-disabled={server.status === 'offline'}
              >
                <div className="flex items-center gap-3">
                  <div className="flex items-center gap-1.5 min-w-[60px]">
                    <span className={`w-2 h-2 rounded-full ${getStatusColor(server.status)}`} aria-hidden="true" />
                    <span className="text-[10px] text-bifrost-text-muted uppercase">
                      {getStatusLabel(server.status)}
                    </span>
                  </div>
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
                    <svg className="w-4 h-4 text-bifrost-success" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
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
