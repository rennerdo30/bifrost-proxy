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
import { APIError, api, formatBytes, getCurrentServerAddress } from '../services/api'
import { getStoredSplitTunnelConfig } from '../services/storage'
import { StatusCard } from '../components/StatusCard'
import { ConnectionStatus, getConnectionStatusColor } from '../utils/status'
import { useToast } from '../components/Toast'

// Constants for exponential backoff
const BASE_RETRY_DELAY = 1000 // 1 second
const MAX_RETRY_DELAY = 30000 // 30 seconds
const MAX_RETRY_COUNT = 5

const STATUS_REFETCH_INTERVAL = 5000
const SERVER_REFETCH_INTERVAL = 30000

export function HomeScreen() {
  const queryClient = useQueryClient()
  const { showToast } = useToast()
  const [isRefreshing, setIsRefreshing] = useState(false)
  const retryCountRef = useRef(0)
  const lastRetryTimeRef = useRef(0)

  const {
    data: status,
    isLoading: statusLoading,
    isError: statusIsError,
    error: statusError,
  } = useQuery({
    queryKey: ['status'],
    queryFn: api.getStatus,
    refetchInterval: STATUS_REFETCH_INTERVAL,
  })

  const {
    data: vpnStatus,
    isLoading: vpnLoading,
    isError: vpnIsError,
    error: vpnError,
  } = useQuery({
    queryKey: ['vpn-status'],
    queryFn: api.getVPNStatus,
    refetchInterval: STATUS_REFETCH_INTERVAL,
  })

  const { data: activeServer } = useQuery({
    queryKey: ['active-server'],
    queryFn: api.getActiveServer,
    refetchInterval: SERVER_REFETCH_INTERVAL,
  })

  /**
   * Push the locally stored split tunnel rules to the client before enabling the
   * VPN, and report how many pushes failed.
   *
   * Known limitation: this only *adds* rules. Rules the operator disabled or
   * deleted on the phone are not removed from the client, because reconciling
   * against the client's own rule set needs `GET /vpn/split/rules` to return
   * a stable JSON shape, which it does not yet (`internal/vpn.SplitTunnelConfig`
   * carries `yaml:` tags only). Sync failures are surfaced rather than swallowed
   * so the operator is not misled about which rules are in force.
   */
  const syncSplitTunnelRules = async (): Promise<number> => {
    let failures = 0
    const push = async (operation: () => Promise<unknown>) => {
      try {
        await operation()
      } catch (error) {
        failures += 1
        console.warn('Split tunnel rule sync failed:', error)
      }
    }

    try {
      const config = await getStoredSplitTunnelConfig()

      await push(() => api.setSplitTunnelMode(config.mode))

      for (const app of config.apps.filter((a) => a.enabled)) {
        await push(() => api.addSplitTunnelApp({ name: app.name, path: app.packageId }))
      }
      for (const domain of config.domains.filter((d) => d.enabled)) {
        await push(() => api.addSplitTunnelDomain(domain.domain))
      }
      for (const ip of config.ips.filter((i) => i.enabled)) {
        await push(() => api.addSplitTunnelIP(ip.cidr))
      }
    } catch (error) {
      // Continue with VPN connection even if the local config cannot be read
      console.warn('Failed to read stored split tunnel rules:', error)
      failures += 1
    }

    return failures
  }

  const connectMutation = useMutation({
    mutationFn: async () => {
      // Sync split tunnel rules before enabling VPN
      const syncFailures = await syncSplitTunnelRules()
      await api.enableVPN()
      return { syncFailures }
    },
    onSuccess: ({ syncFailures }) => {
      queryClient.invalidateQueries({ queryKey: ['vpn-status'] })
      if (syncFailures > 0) {
        showToast(
          `VPN connected, but ${syncFailures} split tunnel rule(s) could not be applied`,
          'error'
        )
        return
      }
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
    } catch {
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

  const isConnected = vpnStatus?.status === 'connected'
  const isToggling = connectMutation.isPending || disconnectMutation.isPending
  const isInitialLoading = statusLoading || vpnLoading

  // The client itself could not be reached. Without this the screen would render
  // "Not Connected" and 0 B, indistinguishable from a healthy idle client.
  const isUnreachable = statusIsError || vpnIsError
  const unreachableError = vpnError ?? statusError
  const unreachableReason =
    unreachableError instanceof APIError && unreachableError.isUnauthorized
      ? 'Authentication failed. Check the API token in Settings.'
      : unreachableError instanceof Error
        ? unreachableError.message
        : 'Could not reach the Bifrost client'

  const getConnectionStatus = (): ConnectionStatus => {
    if (isToggling) return 'connecting'
    if (isUnreachable) return 'unreachable'
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
      case 'unreachable':
        return 'Client Unreachable'
      default:
        return 'Not Connected'
    }
  }

  const getStatusDescription = () => {
    switch (connectionStatus) {
      case 'connected':
        return 'Your connection is secure'
      case 'connecting':
        return 'Establishing secure connection...'
      case 'error':
        return 'Connection failed - tap to retry'
      case 'unreachable':
        return `Cannot reach ${getCurrentServerAddress()} - pull down to retry`
      default:
        return 'Tap the button to connect'
    }
  }

  if (isInitialLoading) {
    return (
      <View style={styles.loadingContainer}>
        <ActivityIndicator size="large" color="#3b82f6" />
        <Text style={styles.loadingText}>Contacting Bifrost client...</Text>
      </View>
    )
  }

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      refreshControl={
        <RefreshControl
          refreshing={isRefreshing}
          onRefresh={onRefresh}
          tintColor="#3b82f6"
          accessibilityLabel="Pull to refresh connection status"
        />
      }
    >
      {/* Connection Status */}
      <View style={styles.statusSection}>
        <View style={[styles.statusRing, { borderColor: statusColor }]}>
          <TouchableOpacity
            style={[styles.connectButton, { backgroundColor: statusColor }]}
            onPress={handleToggle}
            disabled={isToggling || isUnreachable}
            activeOpacity={0.8}
            accessibilityLabel={isConnected ? 'Disconnect from VPN' : 'Connect to VPN'}
            accessibilityRole="button"
            accessibilityState={{ disabled: isToggling || isUnreachable }}
            accessibilityHint={
              isUnreachable
                ? 'The Bifrost client cannot be reached'
                : isToggling
                  ? 'Connection in progress'
                  : undefined
            }
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
        <Text style={styles.statusDescriptionText}>{getStatusDescription()}</Text>
        {status?.version && (
          <Text style={styles.versionText}>v{status.version}</Text>
        )}
      </View>

      {/* Unreachable client */}
      {isUnreachable && (
        <View
          style={styles.errorCard}
          accessible={true}
          accessibilityRole="alert"
          accessibilityLabel={`Client unreachable: ${unreachableReason}`}
        >
          <Text style={styles.errorText} importantForAccessibility="no">
            {unreachableReason}
          </Text>
        </View>
      )}

      {/* Error Message */}
      {!isUnreachable && vpnStatus?.last_error && (
        <View
          style={styles.errorCard}
          accessible={true}
          accessibilityRole="alert"
          accessibilityLabel={`Connection error: ${vpnStatus.last_error}`}
        >
          <Text style={styles.errorText} importantForAccessibility="no">
            {vpnStatus.last_error}
          </Text>
        </View>
      )}

      {/* Stats Cards - suppressed while unreachable so 0 B is never a false reading */}
      {!isUnreachable && (
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
      )}

      {/* Server Info */}
      {isConnected && (
        <View
          style={styles.serverCard}
          accessible={true}
          accessibilityRole="text"
          accessibilityLabel={`Connected to ${activeServer?.name || 'Bifrost Server'} at ${activeServer?.address || getCurrentServerAddress()}`}
        >
          <Text style={styles.serverLabel} importantForAccessibility="no">
            Connected to
          </Text>
          <Text style={styles.serverName} importantForAccessibility="no">
            {activeServer?.name || 'Bifrost Server'}
          </Text>
          <Text style={styles.serverAddress} importantForAccessibility="no">
            {activeServer?.address || getCurrentServerAddress()}
          </Text>
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
  loadingContainer: {
    flex: 1,
    backgroundColor: '#0a0e17',
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20,
  },
  loadingText: {
    marginTop: 12,
    fontSize: 16,
    color: '#6b7280',
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
