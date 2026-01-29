import { useState, useCallback } from 'react'
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
import { api, formatBytes } from '../services/api'
import { StatusCard } from '../components/StatusCard'
import { getConnectionStatusColor } from '../utils/status'

type ConnectionStatus = 'connected' | 'connecting' | 'disconnected' | 'error'

export function HomeScreen() {
  const queryClient = useQueryClient()
  const [isRefreshing, setIsRefreshing] = useState(false)

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

  const connectMutation = useMutation({
    mutationFn: api.enableVPN,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['vpn-status'] }),
  })

  const disconnectMutation = useMutation({
    mutationFn: api.disableVPN,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['vpn-status'] }),
  })

  const onRefresh = useCallback(async () => {
    setIsRefreshing(true)
    await queryClient.invalidateQueries()
    setIsRefreshing(false)
  }, [queryClient])

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
          >
            {isToggling ? (
              <ActivityIndicator size="large" color="#ffffff" />
            ) : (
              <Text style={styles.buttonIcon}>{isConnected ? '🛡️' : '⚡'}</Text>
            )}
          </TouchableOpacity>
        </View>
        <Text style={[styles.statusText, { color: statusColor }]}>{getStatusText()}</Text>
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
          <Text style={styles.serverName}>Primary Server</Text>
          <Text style={styles.serverAddress}>vpn.bifrost.io:8080</Text>
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
