import { useState, useEffect, useCallback } from 'react';

// Wails runtime types
declare global {
  interface Window {
    go: {
      main: {
        App: {
          Connect: () => Promise<void>;
          Disconnect: () => Promise<void>;
          GetStatus: () => Promise<StatusResponse>;
          GetServers: () => Promise<ServerInfo[]>;
          SelectServer: (name: string) => Promise<void>;
          AddServer: (server: ServerConfig) => Promise<void>;
          UpdateServer: (originalName: string, server: ServerConfig) => Promise<void>;
          DeleteServer: (name: string) => Promise<void>;
          SetDefaultServer: (name: string) => Promise<void>;
          GetQuickSettings: () => Promise<QuickSettings>;
          UpdateQuickSettings: (settings: QuickSettings) => Promise<void>;
          GetProxySettings: () => Promise<ProxySettings>;
          UpdateProxySettings: (settings: ProxySettings) => Promise<void>;
          RestartClient: () => Promise<void>;
          EnableVPN: () => Promise<void>;
          DisableVPN: () => Promise<void>;
          OpenWebDashboard: () => Promise<void>;
          Quit: () => Promise<void>;
          IsConnected: () => Promise<boolean>;
          GetAPIBaseURL: () => Promise<string>;
        };
      };
    };
  }
}

export interface StatusResponse {
  status: string;
  version: string;
  server_connected: boolean;
  server_address: string;
  http_proxy: string;
  socks5_proxy: string;
  vpn_enabled: boolean;
  vpn_status: string;
  debug_entries: number;
  uptime: string;
  bytes_sent: number;
  bytes_received: number;
  active_connections: number;
  last_error?: string;
  timestamp: string;
}

export interface ServerInfo {
  name: string;
  address: string;
  protocol: string;
  username?: string;
  password?: string;
  is_default: boolean;
  latency_ms?: number;
  status: string;
}

export interface ServerConfig {
  name: string;
  address: string;
  protocol: string;
  username?: string;
  password?: string;
  is_default?: boolean;
}

export interface QuickSettings {
  auto_connect: boolean;
  start_minimized: boolean;
  show_notifications: boolean;
  vpn_enabled: boolean;
  current_server: string;
}

export interface ProxySettings {
  server_address: string;
  server_protocol: string;
  http_proxy_port: number;
  socks5_proxy_port: number;
}

export type ConnectionStatus = 'connected' | 'connecting' | 'disconnected' | 'error' | 'offline';

// Check if we're running in Wails or browser dev mode
const isWails = () => typeof window !== 'undefined' && window.go !== undefined;

// Mock API for development in browser
const mockAPI = {
  Connect: async () => { if (import.meta.env.DEV) console.log('Mock: Connect'); },
  Disconnect: async () => { if (import.meta.env.DEV) console.log('Mock: Disconnect'); },
  GetStatus: async (): Promise<StatusResponse> => ({
    status: 'running',
    version: '1.0.0-dev',
    server_connected: false,
    server_address: 'demo.bifrost.io:8080',
    http_proxy: '127.0.0.1:3128',
    socks5_proxy: '127.0.0.1:1081',
    vpn_enabled: false,
    vpn_status: 'disabled',
    debug_entries: 42,
    uptime: '00:15:30',
    bytes_sent: 1024 * 1024 * 5,
    bytes_received: 1024 * 1024 * 25,
    active_connections: 3,
    timestamp: new Date().toISOString(),
  }),
  GetServers: async (): Promise<ServerInfo[]> => [
    { name: 'Primary', address: 'us1.bifrost.io:8080', protocol: 'http', is_default: true, latency_ms: 45, status: 'connected' },
    { name: 'Europe', address: 'eu1.bifrost.io:8080', protocol: 'http', is_default: false, latency_ms: 120, status: 'available' },
    { name: 'Asia', address: 'asia1.bifrost.io:8080', protocol: 'socks5', is_default: false, latency_ms: 200, status: 'available' },
  ],
  SelectServer: async (name: string) => { if (import.meta.env.DEV) console.log('Mock: SelectServer', name); },
  AddServer: async (server: ServerConfig) => { if (import.meta.env.DEV) console.log('Mock: AddServer', server); },
  UpdateServer: async (originalName: string, server: ServerConfig) => { if (import.meta.env.DEV) console.log('Mock: UpdateServer', originalName, server); },
  DeleteServer: async (name: string) => { if (import.meta.env.DEV) console.log('Mock: DeleteServer', name); },
  SetDefaultServer: async (name: string) => { if (import.meta.env.DEV) console.log('Mock: SetDefaultServer', name); },
  GetQuickSettings: async (): Promise<QuickSettings> => ({
    auto_connect: true,
    start_minimized: false,
    show_notifications: true,
    vpn_enabled: false,
    current_server: 'Primary',
  }),
  UpdateQuickSettings: async (settings: QuickSettings) => { if (import.meta.env.DEV) console.log('Mock: UpdateQuickSettings', settings); },
  GetProxySettings: async (): Promise<ProxySettings> => ({
    server_address: 'demo.bifrost.io:8080',
    server_protocol: 'http',
    http_proxy_port: 3128,
    socks5_proxy_port: 1081,
  }),
  UpdateProxySettings: async (settings: ProxySettings) => { if (import.meta.env.DEV) console.log('Mock: UpdateProxySettings', settings); },
  RestartClient: async () => { if (import.meta.env.DEV) console.log('Mock: RestartClient'); },
  EnableVPN: async () => { if (import.meta.env.DEV) console.log('Mock: EnableVPN'); },
  DisableVPN: async () => { if (import.meta.env.DEV) console.log('Mock: DisableVPN'); },
  OpenWebDashboard: async () => { window.open('http://127.0.0.1:3129', '_blank'); },
  Quit: async () => { if (import.meta.env.DEV) console.log('Mock: Quit'); },
  IsConnected: async () => false,
  GetAPIBaseURL: async () => 'http://127.0.0.1:7383',
};

// Get the API (real or mock)
const getAPI = () => isWails() ? window.go.main.App : mockAPI;

export function useClient() {
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [servers, setServers] = useState<ServerInfo[]>([]);
  const [settings, setSettings] = useState<QuickSettings | null>(null);
  const [proxySettings, setProxySettings] = useState<ProxySettings | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('offline');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [restarting, setRestarting] = useState(false);

  const api = getAPI();

  // Fetch status
  const refreshStatus = useCallback(async () => {
    try {
      const newStatus = await api.GetStatus();
      setStatus(newStatus);
      setError(null);

      // Determine connection status
      if (newStatus.status === 'offline') {
        setConnectionStatus('offline');
      } else if (newStatus.server_connected) {
        setConnectionStatus('connected');
      } else if (newStatus.last_error) {
        setConnectionStatus('error');
      } else {
        setConnectionStatus('disconnected');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to get status');
      setConnectionStatus('offline');
    }
  }, [api]);

  // Fetch servers
  const refreshServers = useCallback(async () => {
    try {
      const serverList = await api.GetServers();
      setServers(serverList);
    } catch (err) {
      if (import.meta.env.DEV) console.error('Failed to get servers:', err);
      // Only set error on initial load (when servers is empty)
      if (servers.length === 0) {
        setError(err instanceof Error ? err.message : 'Failed to load servers');
      }
    }
  }, [api, servers.length]);

  // Fetch settings
  const refreshSettings = useCallback(async () => {
    try {
      const quickSettings = await api.GetQuickSettings();
      setSettings(quickSettings);
    } catch (err) {
      if (import.meta.env.DEV) console.error('Failed to get settings:', err);
      // Only set error on initial load (when settings is null)
      if (!settings) {
        setError(err instanceof Error ? err.message : 'Failed to load settings');
      }
    }
  }, [api, settings]);

  // Fetch proxy settings
  const refreshProxySettings = useCallback(async () => {
    try {
      const proxy = await api.GetProxySettings();
      setProxySettings(proxy);
    } catch (err) {
      if (import.meta.env.DEV) console.error('Failed to get proxy settings:', err);
      // Only set error on initial load (when proxySettings is null)
      if (!proxySettings) {
        setError(err instanceof Error ? err.message : 'Failed to load proxy settings');
      }
    }
  }, [api, proxySettings]);

  // Connect to server
  const connect = useCallback(async () => {
    setLoading(true);
    setConnectionStatus('connecting');
    setError(null); // Clear previous error on new operation
    try {
      await api.Connect();
      await refreshStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Connection failed');
      setConnectionStatus('error');
    } finally {
      setLoading(false);
    }
  }, [api, refreshStatus]);

  // Disconnect from server
  const disconnect = useCallback(async () => {
    setLoading(true);
    setError(null); // Clear previous error on new operation
    try {
      await api.Disconnect();
      await refreshStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Disconnect failed');
    } finally {
      setLoading(false);
    }
  }, [api, refreshStatus]);

  // Select server
  const selectServer = useCallback(async (name: string) => {
    setError(null); // Clear previous error on new operation
    try {
      await api.SelectServer(name);
      await refreshServers();
      await refreshSettings();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Server selection failed');
    }
  }, [api, refreshServers, refreshSettings]);

  // Add server
  const addServer = useCallback(async (server: ServerConfig) => {
    setError(null);
    try {
      await api.AddServer(server);
      await refreshServers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add server');
      throw err;
    }
  }, [api, refreshServers]);

  // Update server
  const updateServer = useCallback(async (originalName: string, server: ServerConfig) => {
    setError(null);
    try {
      await api.UpdateServer(originalName, server);
      await refreshServers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update server');
      throw err;
    }
  }, [api, refreshServers]);

  // Delete server
  const deleteServer = useCallback(async (name: string) => {
    setError(null);
    try {
      await api.DeleteServer(name);
      await refreshServers();
      await refreshSettings();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete server');
      throw err;
    }
  }, [api, refreshServers, refreshSettings]);

  // Set default server
  const setDefaultServer = useCallback(async (name: string) => {
    setError(null);
    try {
      await api.SetDefaultServer(name);
      await refreshServers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to set default server');
      throw err;
    }
  }, [api, refreshServers]);

  // Update settings
  const updateSettings = useCallback(async (newSettings: Partial<QuickSettings>) => {
    if (!settings) return;
    setError(null); // Clear previous error on new operation
    const updated = { ...settings, ...newSettings };
    try {
      await api.UpdateQuickSettings(updated);
      setSettings(updated);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Settings update failed');
    }
  }, [api, settings]);

  // Update proxy settings
  const updateProxySettings = useCallback(async (newSettings: Partial<ProxySettings>) => {
    if (!proxySettings) return;
    setError(null); // Clear previous error on new operation
    const updated = { ...proxySettings, ...newSettings };
    try {
      await api.UpdateProxySettings(updated);
      setProxySettings(updated);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Proxy settings update failed');
    }
  }, [api, proxySettings]);

  // Restart client
  const restartClient = useCallback(async () => {
    setRestarting(true);
    setError(null); // Clear previous error on new operation
    try {
      await api.RestartClient();
      // Wait a moment for the client to restart
      await new Promise(resolve => setTimeout(resolve, 1000));
      await refreshStatus();
      await refreshProxySettings();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Client restart failed');
    } finally {
      setRestarting(false);
    }
  }, [api, refreshStatus, refreshProxySettings]);

  // Toggle VPN
  const toggleVPN = useCallback(async (enabled: boolean) => {
    setError(null); // Clear previous error on new operation
    try {
      if (enabled) {
        await api.EnableVPN();
      } else {
        await api.DisableVPN();
      }
      await refreshStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'VPN toggle failed');
    }
  }, [api, refreshStatus]);

  // Open web dashboard
  const openDashboard = useCallback(async () => {
    try {
      await api.OpenWebDashboard();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to open dashboard');
    }
  }, [api]);

  // Quit application
  const quit = useCallback(async () => {
    try {
      await api.Quit();
    } catch (err) {
      if (import.meta.env.DEV) console.error('Failed to quit:', err);
    }
  }, [api]);

  // Initial data fetch
  useEffect(() => {
    refreshStatus();
    refreshServers();
    refreshSettings();
    refreshProxySettings();
  }, [refreshStatus, refreshServers, refreshSettings, refreshProxySettings]);

  // Poll status periodically
  useEffect(() => {
    const interval = setInterval(refreshStatus, 5000);
    return () => clearInterval(interval);
  }, [refreshStatus]);

  return {
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
    addServer,
    updateServer,
    deleteServer,
    setDefaultServer,
    updateSettings,
    updateProxySettings,
    restartClient,
    toggleVPN,
    openDashboard,
    quit,
    refreshStatus,
    refreshServers,
    clearError: () => setError(null),
  };
}

// Format bytes to human readable
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}
