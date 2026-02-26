import React, { useState, useEffect, useCallback } from 'react'
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  TextInput,
  Switch,
  ActivityIndicator,
  RefreshControl,
  Alert,
} from 'react-native'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../services/api'
import {
  getStoredSplitTunnelConfig,
  setStoredSplitTunnelConfig,
  StoredSplitTunnelConfig,
  SplitTunnelApp,
  SplitTunnelDomain,
  SplitTunnelIP,
} from '../services/storage'
import { useToast } from '../components/Toast'

type TabType = 'apps' | 'domains' | 'ips'

function SectionHeader({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <View style={styles.sectionHeader}>
      <Text style={styles.sectionTitle}>{title}</Text>
      {subtitle && <Text style={styles.sectionSubtitle}>{subtitle}</Text>}
    </View>
  )
}

function EmptyState({ message }: { message: string }) {
  return (
    <View style={styles.emptyState}>
      <Text style={styles.emptyStateText}>{message}</Text>
    </View>
  )
}

export function SplitTunnelingScreen() {
  const queryClient = useQueryClient()
  const { showToast } = useToast()
  const [activeTab, setActiveTab] = useState<TabType>('apps')
  const [isRefreshing, setIsRefreshing] = useState(false)
  const [localConfig, setLocalConfig] = useState<StoredSplitTunnelConfig | null>(null)
  const [newDomain, setNewDomain] = useState('')
  const [newIP, setNewIP] = useState('')
  const [newAppName, setNewAppName] = useState('')
  const [newAppPackage, setNewAppPackage] = useState('')

  // Fetch server-side split tunnel rules
  const { isLoading: isLoadingRules, refetch: refetchRules } = useQuery({
    queryKey: ['split-tunnel-rules'],
    queryFn: api.getSplitTunnelRules,
    retry: 1,
  })

  // Load local config on mount
  useEffect(() => {
    loadLocalConfig()
  }, [])

  const loadLocalConfig = async () => {
    try {
      const config = await getStoredSplitTunnelConfig()
      setLocalConfig(config)
    } catch {
      showToast('Failed to load configuration', 'error')
    }
  }

  const saveLocalConfig = async (config: StoredSplitTunnelConfig) => {
    try {
      await setStoredSplitTunnelConfig(config)
      setLocalConfig(config)
    } catch {
      showToast('Failed to save configuration', 'error')
    }
  }

  // Mutations for server-side updates
  const setModeMutation = useMutation({
    mutationFn: (mode: 'exclude' | 'include') => api.setSplitTunnelMode(mode),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['split-tunnel-rules'] })
    },
    onError: (error: Error) => {
      showToast(error.message || 'Failed to update mode', 'error')
    },
  })

  const addAppMutation = useMutation({
    mutationFn: (app: { name: string; path?: string }) => api.addSplitTunnelApp(app),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['split-tunnel-rules'] })
      showToast('App added', 'success')
    },
    onError: (error: Error) => {
      showToast(error.message || 'Failed to add app', 'error')
    },
  })

  const removeAppMutation = useMutation({
    mutationFn: (name: string) => api.removeSplitTunnelApp(name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['split-tunnel-rules'] })
      showToast('App removed', 'success')
    },
    onError: (error: Error) => {
      showToast(error.message || 'Failed to remove app', 'error')
    },
  })

  const addDomainMutation = useMutation({
    mutationFn: (domain: string) => api.addSplitTunnelDomain(domain),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['split-tunnel-rules'] })
      showToast('Domain added', 'success')
    },
    onError: (error: Error) => {
      showToast(error.message || 'Failed to add domain', 'error')
    },
  })

  const removeDomainMutation = useMutation({
    mutationFn: (domain: string) => api.removeSplitTunnelDomain(domain),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['split-tunnel-rules'] })
      showToast('Domain removed', 'success')
    },
    onError: (error: Error) => {
      showToast(error.message || 'Failed to remove domain', 'error')
    },
  })

  const addIPMutation = useMutation({
    mutationFn: (cidr: string) => api.addSplitTunnelIP(cidr),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['split-tunnel-rules'] })
      showToast('IP range added', 'success')
    },
    onError: (error: Error) => {
      showToast(error.message || 'Failed to add IP range', 'error')
    },
  })

  const removeIPMutation = useMutation({
    mutationFn: (cidr: string) => api.removeSplitTunnelIP(cidr),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['split-tunnel-rules'] })
      showToast('IP range removed', 'success')
    },
    onError: (error: Error) => {
      showToast(error.message || 'Failed to remove IP range', 'error')
    },
  })

  const onRefresh = useCallback(async () => {
    setIsRefreshing(true)
    await Promise.all([refetchRules(), loadLocalConfig()])
    setIsRefreshing(false)
  }, [refetchRules])

  const handleModeChange = async (newMode: 'exclude' | 'include') => {
    if (!localConfig) return

    // Update local config
    const updatedConfig = { ...localConfig, mode: newMode }
    await saveLocalConfig(updatedConfig)

    // Try to update server (will fail silently if server doesn't support it)
    setModeMutation.mutate(newMode)
  }

  const handleAddApp = async () => {
    const name = newAppName.trim()
    const packageId = newAppPackage.trim()

    if (!name) {
      showToast('App name is required', 'error')
      return
    }

    // Add to local config
    if (localConfig) {
      const newApp: SplitTunnelApp = {
        name,
        packageId: packageId || name,
        enabled: true,
      }
      const updatedConfig = {
        ...localConfig,
        apps: [...localConfig.apps, newApp],
      }
      await saveLocalConfig(updatedConfig)
    }

    // Try to sync with server
    addAppMutation.mutate({ name, path: packageId || undefined })

    setNewAppName('')
    setNewAppPackage('')
  }

  const handleRemoveApp = async (app: SplitTunnelApp) => {
    Alert.alert(
      'Remove App',
      `Remove "${app.name}" from split tunneling?`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Remove',
          style: 'destructive',
          onPress: async () => {
            if (localConfig) {
              const updatedConfig = {
                ...localConfig,
                apps: localConfig.apps.filter((a) => a.packageId !== app.packageId),
              }
              await saveLocalConfig(updatedConfig)
            }
            removeAppMutation.mutate(app.name)
          },
        },
      ]
    )
  }

  const handleToggleApp = async (app: SplitTunnelApp) => {
    if (!localConfig) return

    const updatedApps = localConfig.apps.map((a) =>
      a.packageId === app.packageId ? { ...a, enabled: !a.enabled } : a
    )
    const updatedConfig = { ...localConfig, apps: updatedApps }
    await saveLocalConfig(updatedConfig)
  }

  const validateDomain = (domain: string): boolean => {
    const pattern = /^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/
    return pattern.test(domain)
  }

  const handleAddDomain = async () => {
    const domain = newDomain.trim().toLowerCase()

    if (!domain) {
      showToast('Domain is required', 'error')
      return
    }

    if (!validateDomain(domain)) {
      showToast('Invalid domain format', 'error')
      return
    }

    // Add to local config
    if (localConfig) {
      if (localConfig.domains.some((d) => d.domain === domain)) {
        showToast('Domain already exists', 'error')
        return
      }
      const newDomainEntry: SplitTunnelDomain = { domain, enabled: true }
      const updatedConfig = {
        ...localConfig,
        domains: [...localConfig.domains, newDomainEntry],
      }
      await saveLocalConfig(updatedConfig)
    }

    // Try to sync with server
    addDomainMutation.mutate(domain)
    setNewDomain('')
  }

  const handleRemoveDomain = async (domainEntry: SplitTunnelDomain) => {
    Alert.alert(
      'Remove Domain',
      `Remove "${domainEntry.domain}" from split tunneling?`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Remove',
          style: 'destructive',
          onPress: async () => {
            if (localConfig) {
              const updatedConfig = {
                ...localConfig,
                domains: localConfig.domains.filter((d) => d.domain !== domainEntry.domain),
              }
              await saveLocalConfig(updatedConfig)
            }
            removeDomainMutation.mutate(domainEntry.domain)
          },
        },
      ]
    )
  }

  const handleToggleDomain = async (domainEntry: SplitTunnelDomain) => {
    if (!localConfig) return

    const updatedDomains = localConfig.domains.map((d) =>
      d.domain === domainEntry.domain ? { ...d, enabled: !d.enabled } : d
    )
    const updatedConfig = { ...localConfig, domains: updatedDomains }
    await saveLocalConfig(updatedConfig)
  }

  const validateCIDR = (cidr: string): boolean => {
    // IPv4 CIDR pattern
    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/
    // IPv6 CIDR pattern (simplified)
    const ipv6Pattern = /^([a-fA-F0-9:]+)(\/\d{1,3})?$/

    if (!ipv4Pattern.test(cidr) && !ipv6Pattern.test(cidr)) {
      return false
    }

    // Validate IPv4 octets
    if (ipv4Pattern.test(cidr)) {
      const [ip, prefix] = cidr.split('/')
      const octets = ip.split('.').map(Number)
      if (octets.some((o) => o > 255)) return false
      if (prefix && (Number(prefix) < 0 || Number(prefix) > 32)) return false
    }

    return true
  }

  const handleAddIP = async () => {
    const cidr = newIP.trim()

    if (!cidr) {
      showToast('IP/CIDR is required', 'error')
      return
    }

    if (!validateCIDR(cidr)) {
      showToast('Invalid IP/CIDR format (e.g., 192.168.1.0/24)', 'error')
      return
    }

    // Add to local config
    if (localConfig) {
      if (localConfig.ips.some((i) => i.cidr === cidr)) {
        showToast('IP range already exists', 'error')
        return
      }
      const newIPEntry: SplitTunnelIP = { cidr, enabled: true }
      const updatedConfig = {
        ...localConfig,
        ips: [...localConfig.ips, newIPEntry],
      }
      await saveLocalConfig(updatedConfig)
    }

    // Try to sync with server
    addIPMutation.mutate(cidr)
    setNewIP('')
  }

  const handleRemoveIP = async (ipEntry: SplitTunnelIP) => {
    Alert.alert(
      'Remove IP Range',
      `Remove "${ipEntry.cidr}" from split tunneling?`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Remove',
          style: 'destructive',
          onPress: async () => {
            if (localConfig) {
              const updatedConfig = {
                ...localConfig,
                ips: localConfig.ips.filter((i) => i.cidr !== ipEntry.cidr),
              }
              await saveLocalConfig(updatedConfig)
            }
            removeIPMutation.mutate(ipEntry.cidr)
          },
        },
      ]
    )
  }

  const handleToggleIP = async (ipEntry: SplitTunnelIP) => {
    if (!localConfig) return

    const updatedIPs = localConfig.ips.map((i) =>
      i.cidr === ipEntry.cidr ? { ...i, enabled: !i.enabled } : i
    )
    const updatedConfig = { ...localConfig, ips: updatedIPs }
    await saveLocalConfig(updatedConfig)
  }

  const isLoading = isLoadingRules && !localConfig
  const isMutating =
    setModeMutation.isPending ||
    addAppMutation.isPending ||
    removeAppMutation.isPending ||
    addDomainMutation.isPending ||
    removeDomainMutation.isPending ||
    addIPMutation.isPending ||
    removeIPMutation.isPending

  if (isLoading) {
    return (
      <View style={styles.loadingContainer}>
        <ActivityIndicator size="large" color="#3b82f6" />
        <Text style={styles.loadingText}>Loading configuration...</Text>
      </View>
    )
  }

  const currentMode = localConfig?.mode || 'exclude'
  const apps = localConfig?.apps || []
  const domains = localConfig?.domains || []
  const ips = localConfig?.ips || []

  return (
    <ScrollView
      style={styles.container}
      contentContainerStyle={styles.content}
      refreshControl={
        <RefreshControl refreshing={isRefreshing} onRefresh={onRefresh} tintColor="#3b82f6" />
      }
    >
      {/* Mode Selection */}
      <View style={styles.modeSection}>
        <SectionHeader
          title="Split Tunnel Mode"
          subtitle={
            currentMode === 'exclude'
              ? 'Selected items bypass the VPN'
              : 'Only selected items use the VPN'
          }
        />
        <View style={styles.modeButtons}>
          <TouchableOpacity
            style={[styles.modeButton, currentMode === 'exclude' && styles.modeButtonActive]}
            onPress={() => handleModeChange('exclude')}
            disabled={isMutating}
            accessibilityLabel="Exclude mode"
            accessibilityRole="button"
            accessibilityState={{ selected: currentMode === 'exclude' }}
          >
            <Text
              style={[
                styles.modeButtonText,
                currentMode === 'exclude' && styles.modeButtonTextActive,
              ]}
            >
              Exclude
            </Text>
            <Text style={styles.modeButtonDesc}>Bypass VPN</Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={[styles.modeButton, currentMode === 'include' && styles.modeButtonActive]}
            onPress={() => handleModeChange('include')}
            disabled={isMutating}
            accessibilityLabel="Include mode"
            accessibilityRole="button"
            accessibilityState={{ selected: currentMode === 'include' }}
          >
            <Text
              style={[
                styles.modeButtonText,
                currentMode === 'include' && styles.modeButtonTextActive,
              ]}
            >
              Include
            </Text>
            <Text style={styles.modeButtonDesc}>Use VPN</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* Tab Navigation */}
      <View style={styles.tabContainer}>
        <TouchableOpacity
          style={[styles.tab, activeTab === 'apps' && styles.tabActive]}
          onPress={() => setActiveTab('apps')}
          accessibilityLabel="Apps tab"
          accessibilityRole="tab"
          accessibilityState={{ selected: activeTab === 'apps' }}
        >
          <Text style={[styles.tabText, activeTab === 'apps' && styles.tabTextActive]}>
            Apps ({apps.length})
          </Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.tab, activeTab === 'domains' && styles.tabActive]}
          onPress={() => setActiveTab('domains')}
          accessibilityLabel="Domains tab"
          accessibilityRole="tab"
          accessibilityState={{ selected: activeTab === 'domains' }}
        >
          <Text style={[styles.tabText, activeTab === 'domains' && styles.tabTextActive]}>
            Domains ({domains.length})
          </Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.tab, activeTab === 'ips' && styles.tabActive]}
          onPress={() => setActiveTab('ips')}
          accessibilityLabel="IP Ranges tab"
          accessibilityRole="tab"
          accessibilityState={{ selected: activeTab === 'ips' }}
        >
          <Text style={[styles.tabText, activeTab === 'ips' && styles.tabTextActive]}>
            IPs ({ips.length})
          </Text>
        </TouchableOpacity>
      </View>

      {/* Apps Tab */}
      {activeTab === 'apps' && (
        <View style={styles.tabContent}>
          <SectionHeader
            title="Applications"
            subtitle="Add apps to include/exclude from VPN routing"
          />
          <View style={styles.addForm}>
            <TextInput
              style={[styles.input, styles.inputHalf]}
              value={newAppName}
              onChangeText={setNewAppName}
              placeholder="App name"
              placeholderTextColor="#6b7280"
              autoCapitalize="none"
              autoCorrect={false}
              editable={!isMutating}
            />
            <TextInput
              style={[styles.input, styles.inputHalf]}
              value={newAppPackage}
              onChangeText={setNewAppPackage}
              placeholder="Package ID (optional)"
              placeholderTextColor="#6b7280"
              autoCapitalize="none"
              autoCorrect={false}
              editable={!isMutating}
            />
            <TouchableOpacity
              style={[styles.addButton, isMutating && styles.addButtonDisabled]}
              onPress={handleAddApp}
              disabled={isMutating}
              accessibilityLabel="Add app"
              accessibilityRole="button"
            >
              {addAppMutation.isPending ? (
                <ActivityIndicator size="small" color="#ffffff" />
              ) : (
                <Text style={styles.addButtonText}>Add</Text>
              )}
            </TouchableOpacity>
          </View>
          {apps.length === 0 ? (
            <EmptyState message="No apps configured. Add an app to get started." />
          ) : (
            <View style={styles.listContainer}>
              {apps.map((app) => (
                <View key={app.packageId} style={styles.listItem}>
                  <View style={styles.listItemInfo}>
                    <Text style={styles.listItemTitle}>{app.name}</Text>
                    {app.packageId !== app.name && (
                      <Text style={styles.listItemSubtitle}>{app.packageId}</Text>
                    )}
                  </View>
                  <View style={styles.listItemActions}>
                    <Switch
                      value={app.enabled}
                      onValueChange={() => handleToggleApp(app)}
                      trackColor={{ false: '#374151', true: '#3b82f6' }}
                      thumbColor="#ffffff"
                      disabled={isMutating}
                    />
                    <TouchableOpacity
                      style={styles.removeButton}
                      onPress={() => handleRemoveApp(app)}
                      disabled={isMutating}
                      accessibilityLabel={`Remove ${app.name}`}
                      accessibilityRole="button"
                    >
                      <Text style={styles.removeButtonText}>X</Text>
                    </TouchableOpacity>
                  </View>
                </View>
              ))}
            </View>
          )}
        </View>
      )}

      {/* Domains Tab */}
      {activeTab === 'domains' && (
        <View style={styles.tabContent}>
          <SectionHeader
            title="Domains"
            subtitle="Add domains to include/exclude (supports wildcards like *.example.com)"
          />
          <View style={styles.addForm}>
            <TextInput
              style={[styles.input, styles.inputFull]}
              value={newDomain}
              onChangeText={setNewDomain}
              placeholder="example.com or *.example.com"
              placeholderTextColor="#6b7280"
              autoCapitalize="none"
              autoCorrect={false}
              keyboardType="url"
              editable={!isMutating}
            />
            <TouchableOpacity
              style={[styles.addButton, isMutating && styles.addButtonDisabled]}
              onPress={handleAddDomain}
              disabled={isMutating}
              accessibilityLabel="Add domain"
              accessibilityRole="button"
            >
              {addDomainMutation.isPending ? (
                <ActivityIndicator size="small" color="#ffffff" />
              ) : (
                <Text style={styles.addButtonText}>Add</Text>
              )}
            </TouchableOpacity>
          </View>
          {domains.length === 0 ? (
            <EmptyState message="No domains configured. Add a domain to get started." />
          ) : (
            <View style={styles.listContainer}>
              {domains.map((domainEntry) => (
                <View key={domainEntry.domain} style={styles.listItem}>
                  <View style={styles.listItemInfo}>
                    <Text style={styles.listItemTitle}>{domainEntry.domain}</Text>
                  </View>
                  <View style={styles.listItemActions}>
                    <Switch
                      value={domainEntry.enabled}
                      onValueChange={() => handleToggleDomain(domainEntry)}
                      trackColor={{ false: '#374151', true: '#3b82f6' }}
                      thumbColor="#ffffff"
                      disabled={isMutating}
                    />
                    <TouchableOpacity
                      style={styles.removeButton}
                      onPress={() => handleRemoveDomain(domainEntry)}
                      disabled={isMutating}
                      accessibilityLabel={`Remove ${domainEntry.domain}`}
                      accessibilityRole="button"
                    >
                      <Text style={styles.removeButtonText}>X</Text>
                    </TouchableOpacity>
                  </View>
                </View>
              ))}
            </View>
          )}
        </View>
      )}

      {/* IPs Tab */}
      {activeTab === 'ips' && (
        <View style={styles.tabContent}>
          <SectionHeader
            title="IP Ranges"
            subtitle="Add IP addresses or CIDR ranges (e.g., 192.168.1.0/24)"
          />
          <View style={styles.addForm}>
            <TextInput
              style={[styles.input, styles.inputFull]}
              value={newIP}
              onChangeText={setNewIP}
              placeholder="192.168.1.0/24 or 10.0.0.1"
              placeholderTextColor="#6b7280"
              autoCapitalize="none"
              autoCorrect={false}
              keyboardType="numbers-and-punctuation"
              editable={!isMutating}
            />
            <TouchableOpacity
              style={[styles.addButton, isMutating && styles.addButtonDisabled]}
              onPress={handleAddIP}
              disabled={isMutating}
              accessibilityLabel="Add IP range"
              accessibilityRole="button"
            >
              {addIPMutation.isPending ? (
                <ActivityIndicator size="small" color="#ffffff" />
              ) : (
                <Text style={styles.addButtonText}>Add</Text>
              )}
            </TouchableOpacity>
          </View>
          {ips.length === 0 ? (
            <EmptyState message="No IP ranges configured. Add an IP range to get started." />
          ) : (
            <View style={styles.listContainer}>
              {ips.map((ipEntry) => (
                <View key={ipEntry.cidr} style={styles.listItem}>
                  <View style={styles.listItemInfo}>
                    <Text style={[styles.listItemTitle, styles.monoText]}>{ipEntry.cidr}</Text>
                  </View>
                  <View style={styles.listItemActions}>
                    <Switch
                      value={ipEntry.enabled}
                      onValueChange={() => handleToggleIP(ipEntry)}
                      trackColor={{ false: '#374151', true: '#3b82f6' }}
                      thumbColor="#ffffff"
                      disabled={isMutating}
                    />
                    <TouchableOpacity
                      style={styles.removeButton}
                      onPress={() => handleRemoveIP(ipEntry)}
                      disabled={isMutating}
                      accessibilityLabel={`Remove ${ipEntry.cidr}`}
                      accessibilityRole="button"
                    >
                      <Text style={styles.removeButtonText}>X</Text>
                    </TouchableOpacity>
                  </View>
                </View>
              ))}
            </View>
          )}
        </View>
      )}

      {/* Info Footer */}
      <View style={styles.footer}>
        <Text style={styles.footerText}>
          Split tunneling rules are applied when the VPN connects. Changes take effect on the next connection.
        </Text>
      </View>
    </ScrollView>
  )
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#0a0e17',
  },
  content: {
    padding: 16,
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
  modeSection: {
    marginBottom: 20,
  },
  sectionHeader: {
    marginBottom: 12,
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: '600',
    color: '#f9fafb',
    marginBottom: 4,
  },
  sectionSubtitle: {
    fontSize: 13,
    color: '#6b7280',
  },
  modeButtons: {
    flexDirection: 'row',
    gap: 12,
  },
  modeButton: {
    flex: 1,
    backgroundColor: '#111827',
    borderWidth: 1,
    borderColor: '#1f2937',
    borderRadius: 12,
    padding: 16,
    alignItems: 'center',
  },
  modeButtonActive: {
    borderColor: '#3b82f6',
    backgroundColor: 'rgba(59, 130, 246, 0.1)',
  },
  modeButtonText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#9ca3af',
    marginBottom: 4,
  },
  modeButtonTextActive: {
    color: '#3b82f6',
  },
  modeButtonDesc: {
    fontSize: 12,
    color: '#6b7280',
  },
  tabContainer: {
    flexDirection: 'row',
    backgroundColor: '#111827',
    borderRadius: 12,
    padding: 4,
    marginBottom: 20,
  },
  tab: {
    flex: 1,
    paddingVertical: 10,
    alignItems: 'center',
    borderRadius: 8,
  },
  tabActive: {
    backgroundColor: '#1f2937',
  },
  tabText: {
    fontSize: 14,
    fontWeight: '500',
    color: '#6b7280',
  },
  tabTextActive: {
    color: '#f9fafb',
  },
  tabContent: {
    marginBottom: 20,
  },
  addForm: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
    marginBottom: 16,
  },
  input: {
    backgroundColor: '#111827',
    borderWidth: 1,
    borderColor: '#1f2937',
    borderRadius: 8,
    padding: 12,
    color: '#f9fafb',
    fontSize: 14,
  },
  inputFull: {
    flex: 1,
    minWidth: 200,
  },
  inputHalf: {
    flex: 1,
    minWidth: 120,
  },
  addButton: {
    backgroundColor: '#3b82f6',
    paddingHorizontal: 20,
    paddingVertical: 12,
    borderRadius: 8,
    justifyContent: 'center',
    alignItems: 'center',
    minWidth: 70,
  },
  addButtonDisabled: {
    opacity: 0.6,
  },
  addButtonText: {
    color: '#ffffff',
    fontWeight: '600',
    fontSize: 14,
  },
  emptyState: {
    backgroundColor: '#111827',
    borderWidth: 1,
    borderColor: '#1f2937',
    borderRadius: 12,
    padding: 24,
    alignItems: 'center',
  },
  emptyStateText: {
    color: '#6b7280',
    fontSize: 14,
    textAlign: 'center',
  },
  listContainer: {
    backgroundColor: '#111827',
    borderWidth: 1,
    borderColor: '#1f2937',
    borderRadius: 12,
    overflow: 'hidden',
  },
  listItem: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#1f2937',
  },
  listItemInfo: {
    flex: 1,
    marginRight: 12,
  },
  listItemTitle: {
    fontSize: 15,
    fontWeight: '500',
    color: '#f9fafb',
  },
  listItemSubtitle: {
    fontSize: 12,
    color: '#6b7280',
    marginTop: 2,
  },
  listItemActions: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  removeButton: {
    width: 28,
    height: 28,
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
    borderRadius: 6,
    alignItems: 'center',
    justifyContent: 'center',
  },
  removeButtonText: {
    color: '#ef4444',
    fontSize: 14,
    fontWeight: '600',
  },
  monoText: {
    fontFamily: 'monospace',
  },
  footer: {
    marginTop: 20,
    padding: 16,
    backgroundColor: '#111827',
    borderWidth: 1,
    borderColor: '#1f2937',
    borderRadius: 12,
  },
  footerText: {
    color: '#6b7280',
    fontSize: 13,
    textAlign: 'center',
    lineHeight: 18,
  },
})
