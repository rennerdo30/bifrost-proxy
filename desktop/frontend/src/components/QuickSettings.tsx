import { useState } from 'react';
import { QuickSettings as QuickSettingsType, ProxySettings } from '../hooks/useClient';
import { validateServerAddress } from '../utils/status';

interface QuickSettingsProps {
  settings: QuickSettingsType | null;
  proxySettings: ProxySettings | null;
  onUpdate: (settings: Partial<QuickSettingsType>) => void;
  onUpdateProxy: (settings: Partial<ProxySettings>) => void;
  onRestart: () => void;
  vpnEnabled: boolean;
  onToggleVPN: (enabled: boolean) => void;
  restarting: boolean;
  vpnToggling?: boolean;
}

interface ToggleSwitchProps {
  enabled: boolean;
  onChange: (enabled: boolean) => void;
  label: string;
  description?: string;
  loading?: boolean;
  disabled?: boolean;
}

function ToggleSwitch({ enabled, onChange, label, description, loading, disabled }: ToggleSwitchProps) {
  const isDisabled = loading || disabled;

  return (
    <div className="flex items-center justify-between py-2">
      <div className="flex items-center gap-2">
        <div>
          <p className="text-sm font-medium text-bifrost-text">{label}</p>
          {description && (
            <p className="text-xs text-bifrost-text-muted">{description}</p>
          )}
        </div>
        {loading && (
          <svg
            className="animate-spin w-3.5 h-3.5 text-bifrost-accent"
            fill="none"
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            />
          </svg>
        )}
      </div>
      <button
        onClick={() => !isDisabled && onChange(!enabled)}
        disabled={isDisabled}
        className={`toggle ${enabled ? 'bg-bifrost-accent' : 'bg-bifrost-border'} ${isDisabled ? 'opacity-50 cursor-not-allowed' : ''}`}
        role="switch"
        aria-checked={enabled}
        aria-label={`Toggle ${label}`}
        aria-busy={loading}
      >
        <span
          className={`toggle-dot ${enabled ? 'translate-x-5' : 'translate-x-1'}`}
          aria-hidden="true"
        />
      </button>
    </div>
  );
}

interface CollapsibleSectionProps {
  title: string;
  defaultOpen?: boolean;
  restartRequired?: boolean;
  children: React.ReactNode;
}

function CollapsibleSection({ title, defaultOpen = false, restartRequired, children }: CollapsibleSectionProps) {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  const sectionId = `section-${title.toLowerCase().replace(/\s+/g, '-')}`;

  return (
    <div className="border-t border-bifrost-border/50 pt-2 first:border-t-0 first:pt-0">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between py-2 text-left"
        aria-expanded={isOpen}
        aria-controls={sectionId}
        aria-label={`${isOpen ? 'Collapse' : 'Expand'} ${title} section`}
      >
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-bifrost-text">{title}</span>
          {restartRequired && (
            <span className="px-1.5 py-0.5 text-[10px] font-medium bg-bifrost-warning/20 text-bifrost-warning rounded">
              Restart
            </span>
          )}
        </div>
        <svg
          className={`w-4 h-4 text-bifrost-text-muted transition-transform ${isOpen ? 'rotate-180' : ''}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {isOpen && <div id={sectionId} className="pb-2">{children}</div>}
    </div>
  );
}

export function QuickSettings({
  settings,
  proxySettings,
  onUpdate,
  onUpdateProxy,
  onRestart,
  vpnEnabled,
  onToggleVPN,
  restarting,
  vpnToggling,
}: QuickSettingsProps) {
  const [pendingProxyChanges, setPendingProxyChanges] = useState(false);
  const [localProxy, setLocalProxy] = useState<Partial<ProxySettings>>({});
  const [addressError, setAddressError] = useState<string | null>(null);

  // Show loading skeleton when settings haven't loaded yet
  if (!settings) {
    return (
      <div className="card space-y-1 animate-pulse">
        <div className="h-4 bg-bifrost-border rounded w-24 mb-3" />
        <div className="space-y-3">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="flex items-center justify-between py-2">
              <div className="space-y-1">
                <div className="h-3 bg-bifrost-border rounded w-20" />
                <div className="h-2 bg-bifrost-border rounded w-32" />
              </div>
              <div className="h-6 w-10 bg-bifrost-border rounded-full" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  const handleProxyChange = (field: keyof ProxySettings, value: string | number) => {
    setLocalProxy(prev => ({ ...prev, [field]: value }));
    setPendingProxyChanges(true);
    // Clear address error when user starts typing
    if (field === 'server_address') {
      setAddressError(null);
    }
  };

  const saveProxySettings = () => {
    // Validate server address if it was changed
    if (localProxy.server_address !== undefined) {
      const error = validateServerAddress(localProxy.server_address);
      if (error) {
        setAddressError(error);
        return;
      }
    }
    onUpdateProxy(localProxy);
    setPendingProxyChanges(false);
    setLocalProxy({});
    setAddressError(null);
  };

  const currentProxy = { ...proxySettings, ...localProxy } as ProxySettings;

  return (
    <div className="card space-y-1">
      <h3 className="text-sm font-semibold text-bifrost-text mb-3">Quick Settings</h3>

      <ToggleSwitch
        enabled={vpnEnabled}
        onChange={onToggleVPN}
        label="VPN Mode"
        description="Route all traffic through VPN"
        loading={vpnToggling}
      />

      <ToggleSwitch
        enabled={settings.auto_connect}
        onChange={(enabled) => onUpdate({ auto_connect: enabled })}
        label="Auto-connect"
        description="Connect on startup"
      />

      <ToggleSwitch
        enabled={settings.start_minimized}
        onChange={(enabled) => onUpdate({ start_minimized: enabled })}
        label="Start minimized"
        description="Start in system tray"
      />

      <ToggleSwitch
        enabled={settings.show_notifications}
        onChange={(enabled) => onUpdate({ show_notifications: enabled })}
        label="Notifications"
        description="Show connection alerts"
      />

      {/* Bifrost Server Configuration */}
      <CollapsibleSection title="Bifrost Server" defaultOpen={true} restartRequired>
        <div className="space-y-3 pt-2">
          <p className="text-xs text-bifrost-text-muted">
            Connect to your Bifrost server to route traffic securely.
          </p>

          {/* Server Address */}
          <div>
            <label htmlFor="server-address" className="block text-xs font-medium text-bifrost-text-muted mb-1">
              Server Address
            </label>
            <input
              id="server-address"
              type="text"
              value={currentProxy?.server_address || ''}
              onChange={(e) => handleProxyChange('server_address', e.target.value)}
              placeholder="bifrost.example.com:8080"
              className={`w-full px-3 py-1.5 text-sm bg-bifrost-bg border rounded-md text-bifrost-text placeholder-bifrost-text-muted focus:outline-none focus:ring-1 focus:ring-bifrost-accent focus:border-bifrost-accent ${
                addressError ? 'border-bifrost-error' : 'border-bifrost-border'
              }`}
              aria-invalid={!!addressError}
              aria-describedby={addressError ? 'server-address-error' : undefined}
            />
            {addressError && (
              <p id="server-address-error" className="text-xs text-bifrost-error mt-1">
                {addressError}
              </p>
            )}
          </div>

          {/* Protocol */}
          <div>
            <label htmlFor="server-protocol" className="block text-xs font-medium text-bifrost-text-muted mb-1">
              Connection Protocol
            </label>
            <select
              id="server-protocol"
              value={currentProxy?.server_protocol || 'http'}
              onChange={(e) => handleProxyChange('server_protocol', e.target.value)}
              className="w-full px-3 py-1.5 text-sm bg-bifrost-bg border border-bifrost-border rounded-md text-bifrost-text focus:outline-none focus:ring-1 focus:ring-bifrost-accent focus:border-bifrost-accent"
            >
              <option value="http">HTTP</option>
              <option value="socks5">SOCKS5</option>
            </select>
          </div>
        </div>
      </CollapsibleSection>

      {/* Local Proxy Ports */}
      <CollapsibleSection title="Local Proxy Ports" restartRequired>
        <div className="space-y-3 pt-2">
          <p className="text-xs text-bifrost-text-muted">
            Local ports that apps on this device connect to.
          </p>

          <div className="grid grid-cols-2 gap-2">
            <div>
              <label htmlFor="http-proxy-port" className="block text-xs font-medium text-bifrost-text-muted mb-1">
                HTTP Port
              </label>
              <input
                id="http-proxy-port"
                type="number"
                value={currentProxy?.http_proxy_port || 3128}
                onChange={(e) => handleProxyChange('http_proxy_port', parseInt(e.target.value) || 3128)}
                min={1}
                max={65535}
                className="w-full px-3 py-1.5 text-sm bg-bifrost-bg border border-bifrost-border rounded-md text-bifrost-text focus:outline-none focus:ring-1 focus:ring-bifrost-accent focus:border-bifrost-accent"
              />
            </div>
            <div>
              <label htmlFor="socks5-proxy-port" className="block text-xs font-medium text-bifrost-text-muted mb-1">
                SOCKS5 Port
              </label>
              <input
                id="socks5-proxy-port"
                type="number"
                value={currentProxy?.socks5_proxy_port || 1081}
                onChange={(e) => handleProxyChange('socks5_proxy_port', parseInt(e.target.value) || 1081)}
                min={1}
                max={65535}
                className="w-full px-3 py-1.5 text-sm bg-bifrost-bg border border-bifrost-border rounded-md text-bifrost-text focus:outline-none focus:ring-1 focus:ring-bifrost-accent focus:border-bifrost-accent"
              />
            </div>
          </div>

          {/* Save & Restart Buttons */}
          <div className="flex gap-2 pt-2">
            <button
              onClick={saveProxySettings}
              disabled={!pendingProxyChanges}
              className={`flex-1 px-3 py-1.5 text-sm font-medium rounded-md transition-colors ${
                pendingProxyChanges
                  ? 'bg-bifrost-accent text-white hover:bg-bifrost-accent/90'
                  : 'bg-bifrost-border text-bifrost-text-muted cursor-not-allowed'
              }`}
            >
              Save
            </button>
            <button
              onClick={onRestart}
              disabled={restarting}
              className="flex-1 px-3 py-1.5 text-sm font-medium bg-bifrost-warning/20 text-bifrost-warning rounded-md hover:bg-bifrost-warning/30 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {restarting ? 'Restarting...' : 'Restart Client'}
            </button>
          </div>
        </div>
      </CollapsibleSection>
    </div>
  );
}
