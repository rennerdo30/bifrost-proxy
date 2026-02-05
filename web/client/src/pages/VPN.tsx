import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, VPNConnection } from '../api/client'
import { formatBytes } from '../utils/formatting'
import { validateDomain, validateCIDR } from '../utils/validation'
import { useToast } from '../components/Toast'

export function VPN() {
  const queryClient = useQueryClient()
  const { showToast } = useToast()
  const [newDomain, setNewDomain] = useState('')
  const [newIP, setNewIP] = useState('')
  const [newAppName, setNewAppName] = useState('')
  const [domainError, setDomainError] = useState<string | null>(null)
  const [ipError, setIpError] = useState<string | null>(null)

  const { data: vpnStatus, isLoading: statusLoading } = useQuery({
    queryKey: ['vpn-status'],
    queryFn: api.getVPNStatus,
    refetchInterval: 5000,
  })

  const { data: connections = [] } = useQuery({
    queryKey: ['vpn-connections'],
    queryFn: api.getVPNConnections,
    refetchInterval: 5000,
  })

  const { data: splitRules } = useQuery({
    queryKey: ['vpn-split-rules'],
    queryFn: api.getSplitTunnelRules,
  })

  const [vpnError, setVpnError] = useState<string | null>(null)

  const enableMutation = useMutation({
    mutationFn: api.enableVPN,
    onSuccess: () => {
      setVpnError(null)
      queryClient.invalidateQueries({ queryKey: ['vpn-status'] })
    },
    onError: (error: Error) => {
      setVpnError(error.message || 'Failed to enable VPN. Make sure VPN is configured in Settings.')
    },
  })

  const disableMutation = useMutation({
    mutationFn: api.disableVPN,
    onSuccess: () => {
      setVpnError(null)
      queryClient.invalidateQueries({ queryKey: ['vpn-status'] })
    },
    onError: (error: Error) => {
      setVpnError(error.message || 'Failed to disable VPN')
    },
  })

  const addDomainMutation = useMutation({
    mutationFn: api.addSplitTunnelDomain,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vpn-split-rules'] })
      setNewDomain('')
      setDomainError(null)
      showToast('Domain added to split tunnel rules', 'success')
    },
    onError: (error: Error) => {
      showToast(error.message || 'Failed to add domain', 'error')
    },
  })

  const addIPMutation = useMutation({
    mutationFn: api.addSplitTunnelIP,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vpn-split-rules'] })
      setNewIP('')
      setIpError(null)
      showToast('IP range added to split tunnel rules', 'success')
    },
    onError: (error: Error) => {
      showToast(error.message || 'Failed to add IP range', 'error')
    },
  })

  const addAppMutation = useMutation({
    mutationFn: api.addSplitTunnelApp,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vpn-split-rules'] })
      setNewAppName('')
      showToast('Application added to split tunnel rules', 'success')
    },
    onError: (error: Error) => {
      showToast(error.message || 'Failed to add application', 'error')
    },
  })

  const removeAppMutation = useMutation({
    mutationFn: api.removeSplitTunnelApp,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vpn-split-rules'] })
      showToast('Application removed', 'success')
    },
    onError: (error: Error) => {
      showToast(error.message || 'Failed to remove application', 'error')
    },
  })

  const removeDomainMutation = useMutation({
    mutationFn: api.removeSplitTunnelDomain,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vpn-split-rules'] })
      showToast('Domain removed', 'success')
    },
    onError: (error: Error) => {
      showToast(error.message || 'Failed to remove domain', 'error')
    },
  })

  const removeIPMutation = useMutation({
    mutationFn: api.removeSplitTunnelIP,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vpn-split-rules'] })
      showToast('IP range removed', 'success')
    },
    onError: (error: Error) => {
      showToast(error.message || 'Failed to remove IP range', 'error')
    },
  })

  const setModeMutation = useMutation({
    mutationFn: (mode: 'exclude' | 'include') => api.setSplitTunnelMode(mode),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vpn-split-rules'] })
      showToast('Split tunnel mode updated', 'success')
    },
    onError: (error: Error) => {
      showToast(error.message || 'Failed to change mode', 'error')
    },
  })

  const isEnabled = vpnStatus?.status === 'connected' || vpnStatus?.status === 'running'
  const isToggling = enableMutation.isPending || disableMutation.isPending

  return (
    <div className="space-y-6">
      {/* VPN Status Card */}
      <div className="card">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-4">
            <div className={`w-16 h-16 rounded-full flex items-center justify-center ${
              isEnabled ? 'bg-bifrost-success/20' : 'bg-bifrost-muted/20'
            }`}>
              <svg className={`w-8 h-8 ${isEnabled ? 'text-bifrost-success' : 'text-bifrost-muted'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
              </svg>
            </div>
            <div>
              <h2 className="text-xl font-semibold text-bifrost-text">VPN Mode</h2>
              <p className={`text-sm ${isEnabled ? 'text-bifrost-success' : 'text-bifrost-muted'}`}>
                {statusLoading ? 'Loading...' : isEnabled ? 'Connected' : 'Disconnected'}
              </p>
            </div>
          </div>
          <button
            onClick={() => isEnabled ? disableMutation.mutate() : enableMutation.mutate()}
            disabled={isToggling}
            className={`btn ${isEnabled ? 'btn-danger' : 'btn-success'} min-w-[120px]`}
          >
            {isToggling ? (
              <div className="animate-spin w-4 h-4 border-2 border-white border-t-transparent rounded-full" />
            ) : isEnabled ? (
              'Disconnect'
            ) : (
              'Connect'
            )}
          </button>
        </div>

        {/* VPN Details */}
        {isEnabled && vpnStatus && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-4 border-t border-bifrost-border">
            <div>
              <p className="text-xs text-bifrost-muted">Tunnel Type</p>
              <p className="text-sm font-medium text-bifrost-text">{vpnStatus.tunnel_type || 'TUN'}</p>
            </div>
            <div>
              <p className="text-xs text-bifrost-muted">Interface</p>
              <p className="text-sm font-medium text-bifrost-text font-mono">{vpnStatus.interface_name || 'bifrost0'}</p>
            </div>
            <div>
              <p className="text-xs text-bifrost-muted">Local IP</p>
              <p className="text-sm font-medium text-bifrost-text font-mono">{vpnStatus.local_ip || '-'}</p>
            </div>
            <div>
              <p className="text-xs text-bifrost-muted">Gateway</p>
              <p className="text-sm font-medium text-bifrost-text font-mono">{vpnStatus.gateway || '-'}</p>
            </div>
          </div>
        )}

        {/* Traffic Stats */}
        {vpnStatus && (
          <div className="flex items-center gap-6 mt-4 pt-4 border-t border-bifrost-border">
            <div className="flex items-center gap-2">
              <svg className="w-4 h-4 text-bifrost-success" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 11l5-5m0 0l5 5m-5-5v12" />
              </svg>
              <span className="text-sm text-bifrost-muted">Sent:</span>
              <span className="text-sm font-medium text-bifrost-text">{formatBytes(vpnStatus.bytes_sent)}</span>
            </div>
            <div className="flex items-center gap-2">
              <svg className="w-4 h-4 text-bifrost-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 13l-5 5m0 0l-5-5m5 5V6" />
              </svg>
              <span className="text-sm text-bifrost-muted">Received:</span>
              <span className="text-sm font-medium text-bifrost-text">{formatBytes(vpnStatus.bytes_received)}</span>
            </div>
          </div>
        )}

        {/* Toggle Error */}
        {vpnError && (
          <div className="mt-4 p-3 bg-bifrost-error/10 border border-bifrost-error/30 rounded-lg">
            <p className="text-sm text-bifrost-error font-medium">VPN Toggle Failed</p>
            <p className="text-sm text-bifrost-error mt-1">{vpnError}</p>
            {vpnError.includes('not configured') && (
              <p className="text-xs text-bifrost-muted mt-2">
                Go to <a href="/settings" className="text-bifrost-accent underline">Settings → VPN Mode</a> and enable VPN first.
              </p>
            )}
          </div>
        )}

        {/* Status Error */}
        {vpnStatus?.last_error && (
          <div className="mt-4 p-3 bg-bifrost-error/10 border border-bifrost-error/30 rounded-lg">
            <p className="text-sm text-bifrost-error">{vpnStatus.last_error}</p>
          </div>
        )}

        {/* Not Configured Notice */}
        {!isEnabled && vpnStatus?.status === 'disabled' && (
          <div className="mt-4 p-3 bg-bifrost-muted/10 border border-bifrost-border rounded-lg">
            <p className="text-sm text-bifrost-muted">
              VPN mode is not configured. Enable it in <a href="/settings" className="text-bifrost-accent underline">Settings → VPN Mode</a> to route all traffic through the Bifrost server.
            </p>
          </div>
        )}
      </div>

      {/* Active Connections */}
      <div className="card">
        <h3 className="text-lg font-medium text-bifrost-text mb-4">Active Connections</h3>
        {connections.length === 0 ? (
          <p className="text-sm text-bifrost-muted text-center py-4">No active connections</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-left text-xs text-bifrost-muted border-b border-bifrost-border">
                  <th className="pb-2">Remote</th>
                  <th className="pb-2">Local</th>
                  <th className="pb-2">Protocol</th>
                  <th className="pb-2">Traffic</th>
                </tr>
              </thead>
              <tbody>
                {connections.map((conn: VPNConnection) => (
                  <tr key={conn.id} className="border-b border-bifrost-border/50 text-sm">
                    <td className="py-2 font-mono text-bifrost-text">{conn.remote_addr}</td>
                    <td className="py-2 font-mono text-bifrost-muted">{conn.local_addr}</td>
                    <td className="py-2 text-bifrost-muted">{conn.protocol}</td>
                    <td className="py-2 text-bifrost-muted">
                      {formatBytes(conn.bytes_sent)} / {formatBytes(conn.bytes_received)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Split Tunneling */}
      <div className="card">
        <h3 className="text-lg font-medium text-bifrost-text mb-4 flex items-center gap-2">
          <svg className="w-5 h-5 text-bifrost-accent" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
          </svg>
          Split Tunneling
        </h3>

        <div className="space-y-6">
          {/* Mode */}
          <div>
            <p className="text-sm text-bifrost-muted mb-2">Mode</p>
            <div className="flex gap-2">
              <button
                onClick={() => setModeMutation.mutate('exclude')}
                disabled={setModeMutation.isPending}
                className={`px-3 py-1 rounded text-sm transition-colors ${
                  splitRules?.mode === 'exclude'
                    ? 'bg-bifrost-accent text-white'
                    : 'bg-bifrost-card border border-bifrost-border text-bifrost-muted hover:border-bifrost-accent hover:text-bifrost-accent'
                }`}
              >
                Exclude (bypass VPN)
              </button>
              <button
                onClick={() => setModeMutation.mutate('include')}
                disabled={setModeMutation.isPending}
                className={`px-3 py-1 rounded text-sm transition-colors ${
                  splitRules?.mode === 'include'
                    ? 'bg-bifrost-accent text-white'
                    : 'bg-bifrost-card border border-bifrost-border text-bifrost-muted hover:border-bifrost-accent hover:text-bifrost-accent'
                }`}
              >
                Include (only VPN)
              </button>
            </div>
            <p className="text-xs text-bifrost-muted mt-2">
              {splitRules?.mode === 'exclude'
                ? 'Listed items will bypass the VPN (go direct). All other traffic uses VPN.'
                : 'Only listed items will use the VPN. All other traffic goes direct.'}
            </p>
          </div>

          {/* Apps */}
          <div>
            <label htmlFor="split-tunnel-app" className="block text-sm font-medium text-bifrost-text mb-2">Applications</label>
            <div className="flex gap-2 mb-2">
              <input
                id="split-tunnel-app"
                type="text"
                value={newAppName}
                onChange={(e) => setNewAppName(e.target.value)}
                placeholder="Application name"
                className="input flex-1"
              />
              <button
                onClick={() => newAppName && addAppMutation.mutate({ name: newAppName })}
                disabled={!newAppName || addAppMutation.isPending}
                className="btn btn-primary"
              >
                Add
              </button>
            </div>
            <div className="flex flex-wrap gap-2">
              {splitRules?.apps?.map((app) => (
                <span key={app.name} className="px-2 py-1 bg-bifrost-card border border-bifrost-border rounded text-sm flex items-center gap-2">
                  {app.name}
                  <button
                    onClick={() => removeAppMutation.mutate(app.name)}
                    className="text-bifrost-muted hover:text-bifrost-error"
                    aria-label={`Remove ${app.name}`}
                  >
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </button>
                </span>
              ))}
              {(!splitRules?.apps || splitRules.apps.length === 0) && (
                <span className="text-sm text-bifrost-muted">No applications configured</span>
              )}
            </div>
          </div>

          {/* Domains */}
          <div>
            <label htmlFor="split-tunnel-domain" className="block text-sm font-medium text-bifrost-text mb-2">Domains</label>
            <div className="flex gap-2 mb-2">
              <input
                id="split-tunnel-domain"
                type="text"
                value={newDomain}
                onChange={(e) => {
                  setNewDomain(e.target.value)
                  setDomainError(null)
                }}
                placeholder="*.example.com"
                className={`input flex-1 ${domainError ? 'border-bifrost-error' : ''}`}
              />
              <button
                onClick={() => {
                  if (!newDomain) return
                  const error = validateDomain(newDomain)
                  if (error) {
                    setDomainError(error)
                    return
                  }
                  addDomainMutation.mutate(newDomain)
                }}
                disabled={!newDomain || addDomainMutation.isPending}
                className="btn btn-primary"
              >
                Add
              </button>
            </div>
            {domainError && (
              <p className="text-xs text-bifrost-error mt-1">{domainError}</p>
            )}
            <div className="flex flex-wrap gap-2">
              {splitRules?.domains?.map((domain) => (
                <span key={domain} className="px-2 py-1 bg-bifrost-card border border-bifrost-border rounded text-sm font-mono flex items-center gap-2">
                  {domain}
                  <button
                    onClick={() => removeDomainMutation.mutate(domain)}
                    className="text-bifrost-muted hover:text-bifrost-error"
                    aria-label={`Remove ${domain}`}
                  >
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </button>
                </span>
              ))}
              {(!splitRules?.domains || splitRules.domains.length === 0) && (
                <span className="text-sm text-bifrost-muted">No domains configured</span>
              )}
            </div>
          </div>

          {/* IP Ranges */}
          <div>
            <label htmlFor="split-tunnel-ip" className="block text-sm font-medium text-bifrost-text mb-2">IP Ranges</label>
            <div className="flex gap-2 mb-2">
              <input
                id="split-tunnel-ip"
                type="text"
                value={newIP}
                onChange={(e) => {
                  setNewIP(e.target.value)
                  setIpError(null)
                }}
                placeholder="192.168.1.0/24"
                className={`input flex-1 ${ipError ? 'border-bifrost-error' : ''}`}
              />
              <button
                onClick={() => {
                  if (!newIP) return
                  const error = validateCIDR(newIP)
                  if (error) {
                    setIpError(error)
                    return
                  }
                  addIPMutation.mutate(newIP)
                }}
                disabled={!newIP || addIPMutation.isPending}
                className="btn btn-primary"
              >
                Add
              </button>
            </div>
            {ipError && (
              <p className="text-xs text-bifrost-error mt-1">{ipError}</p>
            )}
            <div className="flex flex-wrap gap-2">
              {splitRules?.ips?.map((ip) => (
                <span key={ip} className="px-2 py-1 bg-bifrost-card border border-bifrost-border rounded text-sm font-mono flex items-center gap-2">
                  {ip}
                  <button
                    onClick={() => removeIPMutation.mutate(ip)}
                    className="text-bifrost-muted hover:text-bifrost-error"
                    aria-label={`Remove ${ip}`}
                  >
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </button>
                </span>
              ))}
              {(!splitRules?.ips || splitRules.ips.length === 0) && (
                <span className="text-sm text-bifrost-muted">No IP ranges configured</span>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
