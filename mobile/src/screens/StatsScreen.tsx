import { useMemo } from 'react'
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  ActivityIndicator,
  TouchableOpacity,
} from 'react-native'
import { useQuery } from '@tanstack/react-query'
import { api, formatBytes, formatUptime } from '../services/api'
import { StatusCard } from '../components/StatusCard'

const COLOR_TEXT = '#f9fafb'
const COLOR_SUCCESS = '#22c55e'
const COLOR_INFO = '#3b82f6'
const COLOR_WARNING = '#f59e0b'
const COLOR_MUTED = '#6b7280'

const VPN_STATUS_REFETCH_INTERVAL = 3000
const STATUS_REFETCH_INTERVAL = 5000

/** Shown when a value genuinely has no reading yet, as opposed to being absent. */
const NO_VALUE = '—'

interface StatRowProps {
  label: string
  value: string
  color?: string
}

function StatRow({ label, value, color = COLOR_TEXT }: StatRowProps) {
  return (
    <View
      style={styles.statRow}
      accessible={true}
      accessibilityRole="text"
      accessibilityLabel={`${label}: ${value}`}
    >
      <Text style={styles.statLabel} importantForAccessibility="no">
        {label}
      </Text>
      <Text style={[styles.statValue, { color }]} importantForAccessibility="no">
        {value}
      </Text>
    </View>
  )
}

/** Format an integer counter, distinguishing "no reading" from a real zero. */
function formatCount(value: number | undefined): string {
  return value == null ? NO_VALUE : value.toLocaleString()
}

export function StatsScreen() {
  const {
    data: vpnStatus,
    isLoading: vpnLoading,
    isError: vpnIsError,
    error: vpnError,
    refetch: refetchVPN,
  } = useQuery({
    queryKey: ['vpn-status'],
    queryFn: api.getVPNStatus,
    refetchInterval: VPN_STATUS_REFETCH_INTERVAL,
  })

  const {
    data: status,
    isLoading: statusLoading,
    isError: statusIsError,
    error: statusError,
    refetch: refetchStatus,
  } = useQuery({
    queryKey: ['status'],
    queryFn: api.getStatus,
    refetchInterval: STATUS_REFETCH_INTERVAL,
  })

  // Session duration comes from `vpn.VPNStats.uptime`, a Go time.Duration.
  const sessionDuration = useMemo(() => formatUptime(vpnStatus?.uptime), [vpnStatus?.uptime])

  const totalBytes = (vpnStatus?.bytes_sent || 0) + (vpnStatus?.bytes_received || 0)

  const isLoading = vpnLoading || statusLoading
  const isError = vpnIsError || statusIsError
  const error = vpnError ?? statusError

  if (isLoading) {
    return (
      <View style={styles.loadingContainer}>
        <ActivityIndicator size="large" color={COLOR_INFO} />
        <Text style={styles.loadingText}>Loading statistics...</Text>
      </View>
    )
  }

  // An unreachable client must not look like an idle one: without this branch a
  // failed fetch renders a full page of zeros.
  if (isError) {
    return (
      <View style={styles.loadingContainer} accessible={true} accessibilityRole="alert">
        <Text style={styles.errorIcon}>!</Text>
        <Text style={styles.errorTitle}>Statistics unavailable</Text>
        <Text style={styles.errorDetail}>
          {error instanceof Error ? error.message : 'Could not reach the Bifrost client'}
        </Text>
        <TouchableOpacity
          style={styles.retryButton}
          onPress={() => {
            void refetchVPN()
            void refetchStatus()
          }}
          accessibilityRole="button"
          accessibilityLabel="Retry loading statistics"
        >
          <Text style={styles.retryButtonText}>Retry</Text>
        </TouchableOpacity>
      </View>
    )
  }

  const serverConnected = status?.server_connected === true

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Overview Cards */}
      <View style={styles.cardsGrid}>
        <StatusCard
          title="Total Sent"
          value={formatBytes(vpnStatus?.bytes_sent || 0)}
          icon="↑"
          color={COLOR_SUCCESS}
        />
        <StatusCard
          title="Total Received"
          value={formatBytes(vpnStatus?.bytes_received || 0)}
          icon="↓"
          color={COLOR_INFO}
        />
      </View>

      {/* Session Stats */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Current Session</Text>
        <View style={styles.statsCard}>
          <StatRow label="Duration" value={sessionDuration ?? NO_VALUE} />
          <StatRow label="Total Data" value={formatBytes(totalBytes)} />
          <StatRow
            label="VPN Status"
            value={vpnStatus?.status ?? NO_VALUE}
            color={vpnStatus?.status === 'connected' ? COLOR_SUCCESS : COLOR_MUTED}
          />
        </View>
      </View>

      {/* Traffic - every field below exists on vpn.VPNStats */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Traffic</Text>
        <View style={styles.statsCard}>
          <StatRow label="Packets Sent" value={formatCount(vpnStatus?.packets_sent)} />
          <StatRow label="Packets Received" value={formatCount(vpnStatus?.packets_received)} />
          <StatRow
            label="Active Connections"
            value={formatCount(vpnStatus?.active_connections)}
          />
        </View>
      </View>

      {/* Split Tunneling */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Split Tunneling</Text>
        <View style={styles.statsCard}>
          <StatRow label="Tunneled" value={formatCount(vpnStatus?.tunneled_connections)} />
          <StatRow label="Bypassed" value={formatCount(vpnStatus?.bypassed_connections)} />
        </View>
      </View>

      {/* DNS */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>DNS</Text>
        <View style={styles.statsCard}>
          <StatRow label="Queries" value={formatCount(vpnStatus?.dns_queries)} />
          <StatRow label="Cache Hits" value={formatCount(vpnStatus?.dns_cache_hits)} />
        </View>
      </View>

      {/* Client Info */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Client Information</Text>
        <View style={styles.statsCard}>
          <StatRow label="Version" value={status?.version || NO_VALUE} />
          <StatRow label="Uptime" value={status?.uptime || NO_VALUE} />
          <StatRow label="Debug Entries" value={formatCount(status?.debug_entries)} />
          <StatRow
            label="Server Status"
            value={serverConnected ? 'Connected' : 'Disconnected'}
            color={serverConnected ? COLOR_SUCCESS : COLOR_WARNING}
          />
          <StatRow label="Server Address" value={status?.server_address || NO_VALUE} />
        </View>
      </View>

      {/* Proxy Listeners */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Proxy Listeners</Text>
        <View style={styles.statsCard}>
          <StatRow label="HTTP" value={status?.http_proxy || NO_VALUE} />
          <StatRow label="SOCKS5" value={status?.socks5_proxy || NO_VALUE} />
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
  errorIcon: {
    fontSize: 48,
    fontWeight: '700',
    color: '#ef4444',
    marginBottom: 12,
  },
  errorTitle: {
    fontSize: 18,
    fontWeight: '600',
    color: '#f9fafb',
    marginBottom: 8,
  },
  errorDetail: {
    fontSize: 14,
    color: '#6b7280',
    textAlign: 'center',
    marginBottom: 20,
  },
  retryButton: {
    backgroundColor: '#3b82f6',
    paddingHorizontal: 24,
    paddingVertical: 12,
    borderRadius: 8,
  },
  retryButtonText: {
    color: '#ffffff',
    fontSize: 16,
    fontWeight: '600',
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
