import { useMemo } from 'react'
import { View, Text, StyleSheet, ScrollView, ActivityIndicator } from 'react-native'
import { useQuery } from '@tanstack/react-query'
import { api, formatBytes, formatDuration } from '../services/api'
import { StatusCard } from '../components/StatusCard'

interface StatRowProps {
  label: string
  value: string
  color?: string
}

function StatRow({ label, value, color = '#f9fafb' }: StatRowProps) {
  return (
    <View style={styles.statRow}>
      <Text style={styles.statLabel}>{label}</Text>
      <Text style={[styles.statValue, { color }]}>{value}</Text>
    </View>
  )
}

export function StatsScreen() {
  const { data: vpnStatus, isLoading: vpnLoading } = useQuery({
    queryKey: ['vpn-status'],
    queryFn: api.getVPNStatus,
    refetchInterval: 3000,
  })

  const { data: status, isLoading: statusLoading } = useQuery({
    queryKey: ['status'],
    queryFn: api.getStatus,
    refetchInterval: 5000,
  })

  // Calculate session duration from connected_since timestamp
  const sessionDuration = useMemo(() => {
    if (!vpnStatus?.connected_since) return 0
    const connectedAt = new Date(vpnStatus.connected_since).getTime()
    const now = Date.now()
    return Math.floor((now - connectedAt) / 1000)
  }, [vpnStatus?.connected_since])

  const totalBytes = (vpnStatus?.bytes_sent || 0) + (vpnStatus?.bytes_received || 0)

  // Format DNS servers list
  const dnsServers = useMemo(() => {
    if (!vpnStatus?.dns_servers || vpnStatus.dns_servers.length === 0) {
      return 'N/A'
    }
    return vpnStatus.dns_servers.join(', ')
  }, [vpnStatus?.dns_servers])

  const isLoading = vpnLoading || statusLoading

  if (isLoading) {
    return (
      <View style={styles.loadingContainer}>
        <ActivityIndicator size="large" color="#3b82f6" />
        <Text style={styles.loadingText}>Loading statistics...</Text>
      </View>
    )
  }

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Overview Cards */}
      <View style={styles.cardsGrid}>
        <StatusCard
          title="Total Sent"
          value={formatBytes(vpnStatus?.bytes_sent || 0)}
          icon="↑"
          color="#22c55e"
        />
        <StatusCard
          title="Total Received"
          value={formatBytes(vpnStatus?.bytes_received || 0)}
          icon="↓"
          color="#3b82f6"
        />
      </View>

      {/* Session Stats */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Current Session</Text>
        <View style={styles.statsCard}>
          <StatRow
            label="Duration"
            value={vpnStatus?.connected_since ? formatDuration(sessionDuration) : 'N/A'}
          />
          <StatRow label="Total Data" value={formatBytes(totalBytes)} />
          <StatRow
            label="Status"
            value={vpnStatus?.status === 'connected' ? 'Connected' : 'Disconnected'}
            color={vpnStatus?.status === 'connected' ? '#22c55e' : '#6b7280'}
          />
        </View>
      </View>

      {/* Connection Info */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Connection Details</Text>
        <View style={styles.statsCard}>
          <StatRow label="Protocol" value={vpnStatus?.tunnel_type || 'N/A'} />
          <StatRow label="Encryption" value={vpnStatus?.encryption || 'N/A'} />
          <StatRow label="Port" value={vpnStatus?.port?.toString() || 'N/A'} />
          <StatRow label="MTU" value={vpnStatus?.mtu?.toString() || 'N/A'} />
        </View>
      </View>

      {/* Client Info */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Client Information</Text>
        <View style={styles.statsCard}>
          <StatRow label="Version" value={status?.version || 'Unknown'} />
          <StatRow label="Debug Entries" value={String(status?.debug_entries || 0)} />
          <StatRow
            label="Server Status"
            value={status?.server_status || 'Unknown'}
            color={status?.server_status === 'connected' ? '#22c55e' : '#f59e0b'}
          />
        </View>
      </View>

      {/* Network Info */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Network</Text>
        <View style={styles.statsCard}>
          <StatRow label="Local IP" value={vpnStatus?.local_ip || 'N/A'} />
          <StatRow label="Gateway" value={vpnStatus?.gateway || 'N/A'} />
          <StatRow label="DNS" value={dnsServers} />
          <StatRow label="Interface" value={vpnStatus?.interface_name || 'N/A'} />
        </View>
      </View>

      {/* Error Display */}
      {vpnStatus?.last_error && (
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>Last Error</Text>
          <View style={styles.errorCard}>
            <Text style={styles.errorText}>{vpnStatus.last_error}</Text>
          </View>
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
    paddingBottom: 40,
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
  cardsGrid: {
    flexDirection: 'row',
    gap: 16,
    marginBottom: 24,
  },
  section: {
    marginBottom: 24,
  },
  sectionTitle: {
    fontSize: 14,
    fontWeight: '600',
    color: '#6b7280',
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginBottom: 12,
  },
  statsCard: {
    backgroundColor: '#111827',
    borderRadius: 16,
    borderWidth: 1,
    borderColor: '#1f2937',
    overflow: 'hidden',
  },
  statRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#1f2937',
  },
  statLabel: {
    fontSize: 15,
    color: '#9ca3af',
  },
  statValue: {
    fontSize: 15,
    fontWeight: '500',
    fontFamily: 'monospace',
  },
  errorCard: {
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
    borderRadius: 16,
    borderWidth: 1,
    borderColor: '#ef4444',
    padding: 16,
  },
  errorText: {
    fontSize: 14,
    color: '#ef4444',
    fontFamily: 'monospace',
  },
})
