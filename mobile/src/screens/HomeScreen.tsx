import { useState, useCallback, useRef } from 'react'
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ActivityIndicator,
  ScrollView,
  RefreshControl,
} from 'react-native'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, formatBytes, getCurrentServerAddress } from '../services/api'
import { getStoredSplitTunnelConfig } from '../services/storage'
import { StatusCard } from '../components/StatusCard'
import { getConnectionStatusColor } from '../utils/status'
import { useToast } from '../components/Toast'

type ConnectionStatus = 'connected' | 'connecting' | 'disconnected' | 'error'

// Constants for exponential backoff
const BASE_RETRY_DELAY = 1000 // 1 second
const MAX_RETRY_DELAY = 30000 // 30 seconds
const MAX_RETRY_COUNT = 5

export function HomeScreen() {
  const queryClient = useQueryClient()
  const { showToast } = useToast()
  const [isRefreshing, setIsRefreshing] = useState(false)
  const retryCountRef = useRef(0)
  const lastRetryTimeRef = useRef(0)

  const { data: status, isLoading: statusLoading } = useQuery({
    queryKey: ['status'],
    queryFn: api.getStatus,
    refetchInterval: 5000,
  })

  const { data: vpnStatus } = useQuery({
    queryKey: ['vpn-status'],
    queryFn: api.getVPNStatus,
    refetchInterval: 5000,
  })

  const { data: activeServer } = useQuery({
    queryKey: ['active-server'],
    queryFn: api.getActiveServer,
    refetchInterval: 30000,
  })

  // Sync split tunnel rules to server before enabling VPN
  const syncSplitTunnelRules = async () => {
    try {
      const config = await getStoredSplitTunnelConfig()

      // Set mode
      await api.setSplitTunnelMode(config.mode).catch(() => {
        // Ignore errors if server doesn't support split tunneling mode endpoint
      })

      // Sync enabled apps
      for (const app of config.apps.filter(a => a.enabled)) {
        await api.addSplitTunnelApp({ name: app.name, path: app.packageId }).catch(() => {
          // Ignore individual app sync errors
        })
      }

      // Sync enabled domains
      for (const domain of config.domains.filter(d => d.enabled)) {
        await api.addSplitTunnelDomain(domain.domain).catch(() => {
          // Ignore individual domain sync errors
        })
      }

      // Sync enabled IPs
      for (const ip of config.ips.filter(i => i.enabled)) {
        await api.addSplitTunnelIP(ip.cidr).catch(() => {
          // Ignore individual IP sync errors
        })
      }
    } catch (error) {
      // Continue with VPN connection even if split tunnel sync fails
      console.warn('Failed to sync split tunnel rules:', error)
    }
  }

  const connectMutation = useMutation({
    mutationFn: async () => {
      // Sync split tunnel rules before enabling VPN
      await syncSplitTunnelRules()
      return api.enableVPN()
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vpn-status'] })
      showToast('VPN connected successfully', 'success')
    },
    onError: (error: Error) => {
      showToast(error.message || 'Failed to connect VPN', 'error')
    },
  })

  const disconnectMutation = useMutation({
    mutationFn: api.disableVPN,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vpn-status'] })
      showToast('VPN disconnected', 'info')
    },
    onError: (error: Error) => {
      showToast(error.message || 'Failed to disconnect VPN', 'error')
    },
  })

  const onRefresh = useCallback(async () => {
    setIsRefreshing(true)

    try {
      // Use refetchQueries instead of invalidateQueries for immediate data refresh
      await queryClient.refetchQueries({
        queryKey: ['status'],
        type: 'active',
      })
      await queryClient.refetchQueries({
        queryKey: ['vpn-status'],
        type: 'active',
      })
      await queryClient.refetchQueries({
        queryKey: ['active-server'],
        type: 'active',
      })

      // Reset retry count on successful refresh
      retryCountRef.current = 0
      lastRetryTimeRef.current = 0
    } catch (error) {
      // Calculate exponential backoff delay
      const now = Date.now()
      const timeSinceLastRetry = now - lastRetryTimeRef.current

      // Reset retry count if enough time has passed (2x max delay)
      if (timeSinceLastRetry > MAX_RETRY_DELAY * 2) {
        retryCountRef.current = 0
      }

      retryCountRef.current = Math.min(retryCountRef.current + 1, MAX_RETRY_COUNT)
      lastRetryTimeRef.current = now

      const backoffDelay = Math.min(
        BASE_RETRY_DELAY * Math.pow(2, retryCountRef.current - 1),
        MAX_RETRY_DELAY
      )

      // Show error toast with backoff information
      if (retryCountRef.current >= MAX_RETRY_COUNT) {
        showToast('Refresh failed. Please check your connection.', 'error')
      } else {
        const nextRetrySeconds = Math.round(backoffDelay / 1000)
        showToast(
          `Refresh failed. Retry in ${nextRetrySeconds}s (attempt ${retryCountRef.current}/${MAX_RETRY_COUNT})`,
          'error'
        )
      }
    } finally {
      setIsRefreshing(false)
    }
  }, [queryClient, showToast])

  const isConnected = vpnStatus?.status === 'connected' || vpnStatus?.status === 'running'
  const isToggling = connectMutation.isPending || disconnectMutation.isPending

  const getConnectionStatus = (): ConnectionStatus => {
    if (isToggling) return 'connecting'
    if (vpnStatus?.last_error) return 'error'
    if (isConnected) return 'connected'
    return 'disconnected'
  }

  const connectionStatus = getConnectionStatus()

  const handleToggle = () => {
    if (isConnected) {
      disconnectMutation.mutate()
    } else {
      connectMutation.mutate()
    }
  }

  const statusColor = getConnectionStatusColor(connectionStatus)

  const getStatusText = () => {
    switch (connectionStatus) {
      case 'connected':
        return 'Protected'
      case 'connecting':
        return 'Connecting...'
      case 'error':
        return 'Error'
      default:
        return 'Not Connected'
    }
  }

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      refreshControl={
        <RefreshControl refreshing={isRefreshing} onRefresh={onRefresh} tintColor="#3b82f6" />
      }
    >
      {/* Connection Status */}
      <View style={styles.statusSection}>
        <View style={[styles.statusRing, { borderColor: statusColor }]}>
          <TouchableOpacity
            style={[styles.connectButton, { backgroundColor: statusColor }]}
            onPress={handleToggle}
            disabled={isToggling}
            activeOpacity={0.8}
            accessibilityLabel={isConnected ? 'Disconnect from VPN' : 'Connect to VPN'}
            accessibilityRole="button"
            accessibilityState={{ disabled: isToggling }}
            accessibilityHint={isToggling ? 'Connection in progress' : undefined}
          >
            {isToggling ? (
              <ActivityIndicator size="large" color="#ffffff" />
            ) : (
              <Text style={styles.buttonIcon}>{isConnected ? '🛡️' : '⚡'}</Text>
            )}
          </TouchableOpacity>
        </View>
        <Text
          style={[styles.statusText, { color: statusColor }]}
          accessibilityRole="text"
          accessibilityLabel={`Connection status: ${getStatusText()}`}
        >
          {getStatusText()}
        </Text>
        <Text style={styles.statusDescriptionText}>
          {connectionStatus === 'connected' && 'Your connection is secure'}
          {connectionStatus === 'connecting' && 'Establishing secure connection...'}
          {connectionStatus === 'error' && 'Connection failed - tap to retry'}
          {connectionStatus === 'disconnected' && 'Tap the button to connect'}
        </Text>
        {status?.version && (
          <Text style={styles.versionText}>v{status.version}</Text>
        )}
      </View>

      {/* Error Message */}
      {vpnStatus?.last_error && (
        <View style={styles.errorCard}>
          <Text style={styles.errorText}>{vpnStatus.last_error}</Text>
        </View>
      )}

      {/* Stats Cards */}
      <View style={styles.statsGrid}>
        <StatusCard
          title="Upload"
          value={formatBytes(vpnStatus?.bytes_sent || 0)}
          icon="↑"
          color="#22c55e"
        />
        <StatusCard
          title="Download"
          value={formatBytes(vpnStatus?.bytes_received || 0)}
          icon="↓"
          color="#3b82f6"
        />
      </View>

      {/* Server Info */}
      {isConnected && (
        <View style={styles.serverCard}>
          <Text style={styles.serverLabel}>Connected to</Text>
          <Text style={styles.serverName}>{activeServer?.name || 'Bifrost Server'}</Text>
          <Text style={styles.serverAddress}>{activeServer?.address || getCurrentServerAddress()}</Text>
        </View>
      )}
    </ScrollView>
  )
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0a0e17',
  },
  content: {
    padding: 20,
    alignItems: 'center',
  },
  statusSection: {
    alignItems: 'center',
    marginVertical: 40,
  },
  statusRing: {
    width: 180,
    height: 180,
    borderRadius: 90,
    borderWidth: 4,
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: 20,
  },
  connectButton: {
    width: 140,
    height: 140,
    borderRadius: 70,
    alignItems: 'center',
    justifyContent: 'center',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 8,
    elevation: 8,
  },
  buttonIcon: {
    fontSize: 48,
  },
  statusText: {
    fontSize: 24,
    fontWeight: '600',
    marginBottom: 4,
  },
  statusDescriptionText: {
    fontSize: 14,
    color: '#6b7280',
    marginBottom: 8,
    textAlign: 'center',
  },
  versionText: {
    fontSize: 14,
    color: '#6b7280',
  },
  errorCard: {
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
    borderWidth: 1,
    borderColor: 'rgba(239, 68, 68, 0.3)',
    borderRadius: 12,
    padding: 16,
    marginBottom: 20,
    width: '100%',
  },
  errorText: {
    color: '#ef4444',
    fontSize: 14,
    textAlign: 'center',
  },
  statsGrid: {
    flexDirection: 'row',
    gap: 16,
    width: '100%',
    marginBottom: 20,
  },
  serverCard: {
    backgroundColor: '#111827',
    borderWidth: 1,
    borderColor: '#1f2937',
    borderRadius: 16,
    padding: 20,
    width: '100%',
    alignItems: 'center',
  },
  serverLabel: {
    fontSize: 12,
    color: '#6b7280',
    marginBottom: 4,
  },
  serverName: {
    fontSize: 18,
    fontWeight: '600',
    color: '#f9fafb',
    marginBottom: 2,
  },
  serverAddress: {
    fontSize: 14,
    color: '#9ca3af',
    fontFamily: 'monospace',
  },
})
