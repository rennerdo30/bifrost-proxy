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
import { formatNumber, t, vpnStatusLabel } from '../i18n'

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
  return value == null ? NO_VALUE : formatNumber(value)
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
        <Text style={styles.loadingText}>{t('stats.loading')}</Text>
      </View>
    )
  }

  // An unreachable client must not look like an idle one: without this branch a
  // failed fetch renders a full page of zeros.
  if (isError) {
    return (
      <View style={styles.loadingContainer} accessible={true} accessibilityRole="alert">
        <Text style={styles.errorIcon}>!</Text>
        <Text style={styles.errorTitle}>{t('stats.unavailable')}</Text>
        <Text style={styles.errorDetail}>
          {error instanceof Error ? error.message : t('stats.unreachable')}
        </Text>
        <TouchableOpacity
          style={styles.retryButton}
          onPress={() => {
            void refetchVPN()
            void refetchStatus()
          }}
          accessibilityRole="button"
          accessibilityLabel={t('stats.retryLabel')}
        >
          <Text style={styles.retryButtonText}>{t('common.retry')}</Text>
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
          title={t('stats.totalSent')}
          value={formatBytes(vpnStatus?.bytes_sent || 0)}
          icon="↑"
          color={COLOR_SUCCESS}
        />
        <StatusCard
          title={t('stats.totalReceived')}
          value={formatBytes(vpnStatus?.bytes_received || 0)}
          icon="↓"
          color={COLOR_INFO}
        />
      </View>

      {/* Session Stats */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>{t('stats.currentSession')}</Text>
        <View style={styles.statsCard}>
          <StatRow label={t('stats.duration')} value={sessionDuration ?? NO_VALUE} />
          <StatRow label={t('stats.totalData')} value={formatBytes(totalBytes)} />
          <StatRow
            label={t('stats.vpnStatus')}
            value={vpnStatus?.status ? vpnStatusLabel(vpnStatus.status) : NO_VALUE}
            color={vpnStatus?.status === 'connected' ? COLOR_SUCCESS : COLOR_MUTED}
          />
        </View>
      </View>

      {/* Traffic - every field below exists on vpn.VPNStats */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>{t('stats.traffic')}</Text>
        <View style={styles.statsCard}>
          <StatRow label={t('stats.packetsSent')} value={formatCount(vpnStatus?.packets_sent)} />
          <StatRow label={t('stats.packetsReceived')} value={formatCount(vpnStatus?.packets_received)} />
          <StatRow
            label={t('stats.activeConnections')}
            value={formatCount(vpnStatus?.active_connections)}
          />
        </View>
      </View>

      {/* Split Tunneling */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>{t('stats.splitTunneling')}</Text>
        <View style={styles.statsCard}>
          <StatRow label={t('stats.tunneled')} value={formatCount(vpnStatus?.tunneled_connections)} />
          <StatRow label={t('stats.bypassed')} value={formatCount(vpnStatus?.bypassed_connections)} />
        </View>
      </View>

      {/* DNS */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>{t('stats.dns')}</Text>
        <View style={styles.statsCard}>
          <StatRow label={t('stats.queries')} value={formatCount(vpnStatus?.dns_queries)} />
          <StatRow label={t('stats.cacheHits')} value={formatCount(vpnStatus?.dns_cache_hits)} />
        </View>
      </View>

      {/* Client Info */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>{t('stats.clientInfo')}</Text>
        <View style={styles.statsCard}>
          <StatRow label={t('stats.version')} value={status?.version || NO_VALUE} />
          <StatRow label={t('stats.uptime')} value={status?.uptime || NO_VALUE} />
          <StatRow label={t('stats.debugEntries')} value={formatCount(status?.debug_entries)} />
          <StatRow
            label={t('stats.serverStatus')}
            value={serverConnected ? t('common.connected') : t('common.disconnected')}
            color={serverConnected ? COLOR_SUCCESS : COLOR_WARNING}
          />
          <StatRow label={t('stats.serverAddress')} value={status?.server_address || NO_VALUE} />
        </View>
      </View>

      {/* Proxy Listeners */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>{t('stats.proxyListeners')}</Text>
        <View style={styles.statsCard}>
          <StatRow label="HTTP" value={status?.http_proxy || NO_VALUE} />
          <StatRow label="SOCKS5" value={status?.socks5_proxy || NO_VALUE} />
        </View>
      </View>

      {/* Error Display */}
      {vpnStatus?.last_error && (
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>{t('stats.lastError')}</Text>
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
