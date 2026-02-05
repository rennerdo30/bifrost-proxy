import { useState, useEffect } from 'react'
import {
  View,
  Text,
  StyleSheet,
  FlatList,
  TouchableOpacity,
  ActivityIndicator,
  RefreshControl,
} from 'react-native'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, ServerInfo } from '../services/api'
import { getStatusColor } from '../utils/status'

export function ServersScreen() {
  const queryClient = useQueryClient()
  const [selectedServer, setSelectedServer] = useState<string | null>(null)

  const {
    data: servers,
    isLoading,
    error,
    refetch,
    isRefetching,
  } = useQuery({
    queryKey: ['servers'],
    queryFn: api.getServers,
    refetchInterval: 30000,
  })

  const selectMutation = useMutation({
    mutationFn: (id: string) => api.selectServer(id),
    onSuccess: (_data, id) => {
      setSelectedServer(id)
      queryClient.invalidateQueries({ queryKey: ['servers'] })
    },
  })

  // Set initial selected server from default
  useEffect(() => {
    if (servers && !selectedServer) {
      const defaultServer = servers.find((s) => s.is_default)
      if (defaultServer) {
        setSelectedServer(defaultServer.id)
      }
    }
  }, [servers, selectedServer])

  const handleSelectServer = (id: string) => {
    const server = servers?.find((s) => s.id === id)
    if (server?.status === 'offline') return

    selectMutation.mutate(id)
  }

  const renderServer = ({ item }: { item: ServerInfo }) => {
    const isSelected = selectedServer === item.id
    const isDisabled = item.status === 'offline'
    const isConnecting = selectMutation.isPending && selectMutation.variables === item.id

    // Build accessibility label with all relevant server info
    const statusText = isDisabled ? 'offline' : item.status
    const selectedText = isSelected ? ', currently selected' : ''
    const defaultText = item.is_default ? ', default server' : ''
    const latencyText = item.latency_ms != null && item.latency_ms > 0 ? `, latency ${item.latency_ms} milliseconds` : ''
    const connectingText = isConnecting ? ', connecting' : ''
    const accessibilityLabel = `${item.name}, ${item.address}, ${item.protocol}, ${statusText}${defaultText}${selectedText}${latencyText}${connectingText}`

    return (
      <TouchableOpacity
        style={[
          styles.serverCard,
          isSelected && styles.serverCardSelected,
          isDisabled && styles.serverCardDisabled,
        ]}
        onPress={() => handleSelectServer(item.id)}
        disabled={isDisabled || selectMutation.isPending}
        activeOpacity={0.7}
        accessibilityRole="button"
        accessibilityLabel={accessibilityLabel}
        accessibilityState={{
          disabled: isDisabled,
          selected: isSelected,
          busy: isConnecting,
        }}
        accessibilityHint={isDisabled ? 'Server is offline and cannot be selected' : 'Double tap to connect to this server'}
      >
        <View style={styles.serverHeader}>
          <View style={styles.serverInfo}>
            <View style={styles.nameRow}>
              <Text style={[styles.serverName, isDisabled && styles.textDisabled]}>
                {item.name}
              </Text>
              {item.is_default && (
                <View style={styles.defaultBadge}>
                  <Text style={styles.defaultText}>Default</Text>
                </View>
              )}
            </View>
            <Text style={[styles.serverAddress, isDisabled && styles.textDisabled]}>
              {item.address}
            </Text>
          </View>
          <View style={styles.serverMeta}>
            <View style={[styles.statusDot, { backgroundColor: getStatusColor(item.status) }]} />
            {isSelected && !isConnecting && (
              <Text style={styles.checkmark}>✓</Text>
            )}
            {isConnecting && (
              <ActivityIndicator size="small" color="#3b82f6" />
            )}
          </View>
        </View>
        <View style={styles.serverFooter}>
          <Text style={[styles.protocolBadge, isDisabled && styles.textDisabled]}>
            {item.protocol}
          </Text>
          {item.latency_ms != null && item.latency_ms > 0 && (
            <Text style={[styles.latencyText, isDisabled && styles.textDisabled]}>
              {item.latency_ms}ms
            </Text>
          )}
        </View>
      </TouchableOpacity>
    )
  }

  if (isLoading) {
    return (
      <View style={styles.centerContainer}>
        <ActivityIndicator size="large" color="#3b82f6" />
        <Text style={styles.loadingText}>Loading servers...</Text>
      </View>
    )
  }

  if (error) {
    return (
      <View style={styles.centerContainer}>
        <Text style={styles.errorIcon}>!</Text>
        <Text style={styles.errorText}>Failed to load servers</Text>
        <Text style={styles.errorDetail}>
          {error instanceof Error ? error.message : 'Unknown error'}
        </Text>
        <TouchableOpacity
          style={styles.retryButton}
          onPress={() => refetch()}
          accessibilityRole="button"
          accessibilityLabel="Retry loading servers"
          accessibilityHint="Double tap to retry loading the server list"
        >
          <Text style={styles.retryButtonText}>Retry</Text>
        </TouchableOpacity>
      </View>
    )
  }

  return (
    <View style={styles.container}>
      <Text style={styles.sectionTitle}>Available Servers</Text>
      {selectMutation.isError && (
        <View style={styles.errorBanner}>
          <Text style={styles.errorBannerText}>
            Failed to connect: {selectMutation.error instanceof Error ? selectMutation.error.message : 'Unknown error'}
          </Text>
        </View>
      )}
      <FlatList
        data={servers}
        renderItem={renderServer}
        keyExtractor={(item) => item.id}
        contentContainerStyle={styles.listContent}
        showsVerticalScrollIndicator={false}
        refreshControl={
          <RefreshControl
            refreshing={isRefetching}
            onRefresh={() => refetch()}
            tintColor="#3b82f6"
            colors={['#3b82f6']}
            accessibilityLabel="Pull to refresh server list"
          />
        }
        ListEmptyComponent={
          <View style={styles.emptyContainer}>
            <Text style={styles.emptyText}>No servers configured</Text>
            <Text style={styles.emptySubtext}>Add servers in your client configuration</Text>
          </View>
        }
      />
    </View>
  )
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0a0e17',
    padding: 20,
  },
  centerContainer: {
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
  errorText: {
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
  errorBanner: {
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
    borderWidth: 1,
    borderColor: '#ef4444',
    borderRadius: 8,
    padding: 12,
    marginBottom: 12,
  },
  errorBannerText: {
    color: '#ef4444',
    fontSize: 14,
  },
  sectionTitle: {
    fontSize: 14,
    fontWeight: '600',
    color: '#6b7280',
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginBottom: 12,
  },
  listContent: {
    gap: 12,
  },
  emptyContainer: {
    alignItems: 'center',
    paddingVertical: 40,
  },
  emptyText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#6b7280',
    marginBottom: 4,
  },
  emptySubtext: {
    fontSize: 14,
    color: '#4b5563',
  },
  serverCard: {
    backgroundColor: '#111827',
    borderWidth: 1,
    borderColor: '#1f2937',
    borderRadius: 16,
    padding: 16,
  },
  serverCardSelected: {
    borderColor: '#3b82f6',
    backgroundColor: 'rgba(59, 130, 246, 0.1)',
  },
  serverCardDisabled: {
    opacity: 0.5,
  },
  serverHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 12,
  },
  serverInfo: {
    flex: 1,
  },
  nameRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 4,
  },
  serverName: {
    fontSize: 18,
    fontWeight: '600',
    color: '#f9fafb',
  },
  defaultBadge: {
    backgroundColor: 'rgba(59, 130, 246, 0.2)',
    paddingHorizontal: 8,
    paddingVertical: 2,
    borderRadius: 4,
  },
  defaultText: {
    fontSize: 10,
    fontWeight: '600',
    color: '#3b82f6',
    textTransform: 'uppercase',
  },
  serverAddress: {
    fontSize: 14,
    color: '#9ca3af',
    fontFamily: 'monospace',
  },
  serverMeta: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  statusDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
  },
  checkmark: {
    fontSize: 20,
    color: '#3b82f6',
    fontWeight: '700',
  },
  serverFooter: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  protocolBadge: {
    fontSize: 12,
    color: '#9ca3af',
    backgroundColor: '#1f2937',
    paddingHorizontal: 8,
    paddingVertical: 4,
    borderRadius: 4,
    overflow: 'hidden',
  },
  latencyText: {
    fontSize: 12,
    color: '#6b7280',
  },
  textDisabled: {
    color: '#4b5563',
  },
})
