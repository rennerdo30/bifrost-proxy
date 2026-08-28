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
import { reconcileSplitTunnelConfig } from '../services/splitTunnelSync'
import { t } from '../i18n'

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

  // Fetch the remote client's active split-tunnel policy. The data is merged
  // into the local editor model below; it is never fetched and discarded.
  const {
    data: remoteConfig,
    isLoading: isLoadingRules,
    error: rulesError,
    refetch: refetchRules,
  } = useQuery({
    queryKey: ['split-tunnel-rules'],
    queryFn: api.getSplitTunnelRules,
    retry: 1,
  })

  const loadLocalConfig = useCallback(async () => {
    try {
      const config = await getStoredSplitTunnelConfig()
      setLocalConfig(config)
    } catch {
      showToast(t('split.loadFailed'), 'error')
    }
  }, [showToast])

  const saveLocalConfig = useCallback(
    async (config: StoredSplitTunnelConfig) => {
      try {
        await setStoredSplitTunnelConfig(config)
        setLocalConfig(config)
      } catch {
        showToast(t('split.saveFailed'), 'error')
      }
    },
    [showToast]
  )

  // Load the locally remembered editor state on mount.
  useEffect(() => {
    void loadLocalConfig()
  }, [loadLocalConfig])

  // Remote rules are the source of truth for what is active now. Import remote
  // additions and mark locally remembered-but-absent rules disabled. Equality
  // check prevents a storage/state loop after writing the reconciled model.
  useEffect(() => {
    if (!localConfig || !remoteConfig) return
    const reconciled = reconcileSplitTunnelConfig(localConfig, remoteConfig)
    if (JSON.stringify(reconciled) !== JSON.stringify(localConfig)) {
      void saveLocalConfig(reconciled)
    }
  }, [localConfig, remoteConfig, saveLocalConfig])

  // Mutations for server-side updates
  const setModeMutation = useMutation({
    mutationFn: (mode: 'exclude' | 'include') => api.setSplitTunnelMode(mode),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['split-tunnel-rules'] })
    },
    onError: (error: Error) => {
      showToast(error.message || t('split.modeFailed'), 'error')
    },
  })

  const addAppMutation = useMutation({
    mutationFn: (app: { name: string; path?: string }) => api.addSplitTunnelApp(app),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['split-tunnel-rules'] })
      showToast(t('split.appAdded'), 'success')
    },
    onError: (error: Error) => {
      showToast(error.message || t('split.appAddFailed'), 'error')
    },
  })

  const removeAppMutation = useMutation({
    mutationFn: ({ name }: { name: string; retainLocal: boolean }) =>
      api.removeSplitTunnelApp(name),
    onSuccess: async (_, { name, retainLocal }) => {
      if (localConfig) {
        const apps = retainLocal
          ? localConfig.apps.map((app) =>
              app.name === name ? { ...app, enabled: false } : app
            )
          : localConfig.apps.filter((app) => app.name !== name)
        await saveLocalConfig({ ...localConfig, apps })
      }
      queryClient.invalidateQueries({ queryKey: ['split-tunnel-rules'] })
      showToast(retainLocal ? t('split.appDisabled') : t('split.appRemoved'), 'success')
    },
    onError: (error: Error) => {
      showToast(error.message || t('split.appRemoveFailed'), 'error')
    },
  })

  const addDomainMutation = useMutation({
    mutationFn: (domain: string) => api.addSplitTunnelDomain(domain),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['split-tunnel-rules'] })
      showToast(t('split.domainAdded'), 'success')
    },
    onError: (error: Error) => {
      showToast(error.message || t('split.domainAddFailed'), 'error')
    },
  })

  const removeDomainMutation = useMutation({
    mutationFn: ({ domain }: { domain: string; retainLocal: boolean }) =>
      api.removeSplitTunnelDomain(domain),
    onSuccess: async (_, { domain, retainLocal }) => {
      if (localConfig) {
        const domains = retainLocal
          ? localConfig.domains.map((item) =>
              item.domain === domain ? { ...item, enabled: false } : item
            )
          : localConfig.domains.filter((item) => item.domain !== domain)
        await saveLocalConfig({ ...localConfig, domains })
      }
      queryClient.invalidateQueries({ queryKey: ['split-tunnel-rules'] })
      showToast(retainLocal ? t('split.domainDisabled') : t('split.domainRemoved'), 'success')
    },
    onError: (error: Error) => {
      showToast(error.message || t('split.domainRemoveFailed'), 'error')
    },
  })

  const addIPMutation = useMutation({
    mutationFn: (cidr: string) => api.addSplitTunnelIP(cidr),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['split-tunnel-rules'] })
      showToast(t('split.ipAdded'), 'success')
    },
    onError: (error: Error) => {
      showToast(error.message || t('split.ipAddFailed'), 'error')
    },
  })

  const removeIPMutation = useMutation({
    mutationFn: ({ cidr }: { cidr: string; retainLocal: boolean }) =>
      api.removeSplitTunnelIP(cidr),
    onSuccess: async (_, { cidr, retainLocal }) => {
      if (localConfig) {
        const ips = retainLocal
          ? localConfig.ips.map((item) =>
              item.cidr === cidr ? { ...item, enabled: false } : item
            )
          : localConfig.ips.filter((item) => item.cidr !== cidr)
        await saveLocalConfig({ ...localConfig, ips })
      }
      queryClient.invalidateQueries({ queryKey: ['split-tunnel-rules'] })
      showToast(retainLocal ? t('split.ipDisabled') : t('split.ipRemoved'), 'success')
    },
    onError: (error: Error) => {
      showToast(error.message || t('split.ipRemoveFailed'), 'error')
    },
  })

  const onRefresh = useCallback(async () => {
    setIsRefreshing(true)
    await Promise.all([refetchRules(), loadLocalConfig()])
    setIsRefreshing(false)
  }, [refetchRules, loadLocalConfig])

  const handleModeChange = (newMode: 'exclude' | 'include') => {
    // The remote client is canonical; the query refetch reconciles local
    // storage after the mutation succeeds.
    setModeMutation.mutate(newMode)
  }

  const handleAddApp = async () => {
    const name = newAppName.trim()
    const packageId = newAppPackage.trim()

    if (!name) {
      showToast(t('split.appNameRequired'), 'error')
      return
    }

    addAppMutation.mutate({ name, path: packageId || undefined })

    setNewAppName('')
    setNewAppPackage('')
  }

  const handleRemoveApp = async (app: SplitTunnelApp) => {
    Alert.alert(
      t('split.removeAppTitle'),
      t('split.removeAppMessage', { name: app.name }),
      [
        { text: t('common.cancel'), style: 'cancel' },
        {
          text: t('common.remove'),
          style: 'destructive',
          onPress: () => {
            removeAppMutation.mutate({ name: app.name, retainLocal: false })
          },
        },
      ]
    )
  }

  const handleToggleApp = (app: SplitTunnelApp) => {
    if (app.enabled) {
      removeAppMutation.mutate({ name: app.name, retainLocal: true })
    } else {
      addAppMutation.mutate({ name: app.name, path: app.packageId || undefined })
    }
  }

  const validateDomain = (domain: string): boolean => {
    const pattern = /^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/
    return pattern.test(domain)
  }

  const handleAddDomain = async () => {
    const domain = newDomain.trim().toLowerCase()

    if (!domain) {
      showToast(t('split.domainRequired'), 'error')
      return
    }

    if (!validateDomain(domain)) {
      showToast(t('split.invalidDomain'), 'error')
      return
    }

    if (localConfig?.domains.some((d) => d.domain === domain && d.enabled)) {
      showToast(t('split.domainExists'), 'error')
      return
    }

    addDomainMutation.mutate(domain)
    setNewDomain('')
  }

  const handleRemoveDomain = async (domainEntry: SplitTunnelDomain) => {
    Alert.alert(
      t('split.removeDomainTitle'),
      t('split.removeDomainMessage', { domain: domainEntry.domain }),
      [
        { text: t('common.cancel'), style: 'cancel' },
        {
          text: t('common.remove'),
          style: 'destructive',
          onPress: () => {
            removeDomainMutation.mutate({ domain: domainEntry.domain, retainLocal: false })
          },
        },
      ]
    )
  }

  const handleToggleDomain = (domainEntry: SplitTunnelDomain) => {
    if (domainEntry.enabled) {
      removeDomainMutation.mutate({ domain: domainEntry.domain, retainLocal: true })
    } else {
      addDomainMutation.mutate(domainEntry.domain)
    }
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
      showToast(t('split.ipRequired'), 'error')
      return
    }

    if (!validateCIDR(cidr)) {
      showToast(t('split.invalidIP'), 'error')
      return
    }

    if (localConfig?.ips.some((item) => item.cidr === cidr && item.enabled)) {
      showToast(t('split.ipExists'), 'error')
      return
    }

    addIPMutation.mutate(cidr)
    setNewIP('')
  }

  const handleRemoveIP = async (ipEntry: SplitTunnelIP) => {
    Alert.alert(
      t('split.removeIPTitle'),
      t('split.removeIPMessage', { cidr: ipEntry.cidr }),
      [
        { text: t('common.cancel'), style: 'cancel' },
        {
          text: t('common.remove'),
          style: 'destructive',
          onPress: () => {
            removeIPMutation.mutate({ cidr: ipEntry.cidr, retainLocal: false })
          },
        },
      ]
    )
  }

  const handleToggleIP = (ipEntry: SplitTunnelIP) => {
    if (ipEntry.enabled) {
      removeIPMutation.mutate({ cidr: ipEntry.cidr, retainLocal: true })
    } else {
      addIPMutation.mutate(ipEntry.cidr)
    }
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
        <Text style={styles.loadingText}>{t('split.loading')}</Text>
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
      {rulesError && (
        <View style={styles.errorCard} accessible={true} accessibilityRole="alert">
          <Text style={styles.errorText}>{t('split.remoteLoadFailed')}</Text>
          <Text style={styles.errorDetail}>
            {rulesError instanceof Error ? rulesError.message : t('common.unknownError')}
          </Text>
          <Text style={styles.errorDetail}>{t('split.localFallback')}</Text>
        </View>
      )}

      {/* Mode Selection */}
      <View style={styles.modeSection}>
        <SectionHeader
          title={t('split.modeTitle')}
          subtitle={
            currentMode === 'exclude'
              ? t('split.excludeSubtitle')
              : t('split.includeSubtitle')
          }
        />
        <View style={styles.modeButtons}>
          <TouchableOpacity
            style={[styles.modeButton, currentMode === 'exclude' && styles.modeButtonActive]}
            onPress={() => handleModeChange('exclude')}
            disabled={isMutating}
            accessibilityLabel={t('split.exclude')}
            accessibilityRole="button"
            accessibilityState={{ selected: currentMode === 'exclude' }}
          >
            <Text
              style={[
                styles.modeButtonText,
                currentMode === 'exclude' && styles.modeButtonTextActive,
              ]}
            >
              {t('split.exclude')}
            </Text>
            <Text style={styles.modeButtonDesc}>{t('split.bypassVPN')}</Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={[styles.modeButton, currentMode === 'include' && styles.modeButtonActive]}
            onPress={() => handleModeChange('include')}
            disabled={isMutating}
            accessibilityLabel={t('split.include')}
            accessibilityRole="button"
            accessibilityState={{ selected: currentMode === 'include' }}
          >
            <Text
              style={[
                styles.modeButtonText,
                currentMode === 'include' && styles.modeButtonTextActive,
              ]}
            >
              {t('split.include')}
            </Text>
            <Text style={styles.modeButtonDesc}>{t('split.useVPN')}</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* Tab Navigation */}
      <View style={styles.tabContainer}>
        <TouchableOpacity
          style={[styles.tab, activeTab === 'apps' && styles.tabActive]}
          onPress={() => setActiveTab('apps')}
          accessibilityLabel={t('split.appsTab')}
          accessibilityRole="tab"
          accessibilityState={{ selected: activeTab === 'apps' }}
        >
          <Text style={[styles.tabText, activeTab === 'apps' && styles.tabTextActive]}>
            {t('split.appsCount', { count: apps.length })}
          </Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.tab, activeTab === 'domains' && styles.tabActive]}
          onPress={() => setActiveTab('domains')}
          accessibilityLabel={t('split.domainsTab')}
          accessibilityRole="tab"
          accessibilityState={{ selected: activeTab === 'domains' }}
        >
          <Text style={[styles.tabText, activeTab === 'domains' && styles.tabTextActive]}>
            {t('split.domainsCount', { count: domains.length })}
          </Text>
        </TouchableOpacity>
        <TouchableOpacity
          style={[styles.tab, activeTab === 'ips' && styles.tabActive]}
          onPress={() => setActiveTab('ips')}
          accessibilityLabel={t('split.ipsTab')}
          accessibilityRole="tab"
          accessibilityState={{ selected: activeTab === 'ips' }}
        >
          <Text style={[styles.tabText, activeTab === 'ips' && styles.tabTextActive]}>
            {t('split.ipsCount', { count: ips.length })}
          </Text>
        </TouchableOpacity>
      </View>

      {/* Apps Tab */}
      {activeTab === 'apps' && (
        <View style={styles.tabContent}>
          <SectionHeader
            title={t('split.applications')}
            subtitle={t('split.appsSubtitle')}
          />
          <View style={styles.addForm}>
            <TextInput
              style={[styles.input, styles.inputHalf]}
              value={newAppName}
              onChangeText={setNewAppName}
              placeholder={t('split.appNamePlaceholder')}
              placeholderTextColor="#6b7280"
              autoCapitalize="none"
              autoCorrect={false}
              editable={!isMutating}
            />
            <TextInput
              style={[styles.input, styles.inputHalf]}
              value={newAppPackage}
              onChangeText={setNewAppPackage}
              placeholder={t('split.packagePlaceholder')}
              placeholderTextColor="#6b7280"
              autoCapitalize="none"
              autoCorrect={false}
              editable={!isMutating}
            />
            <TouchableOpacity
              style={[styles.addButton, isMutating && styles.addButtonDisabled]}
              onPress={handleAddApp}
              disabled={isMutating}
              accessibilityLabel={t('split.addApp')}
              accessibilityRole="button"
            >
              {addAppMutation.isPending ? (
                <ActivityIndicator size="small" color="#ffffff" />
              ) : (
                <Text style={styles.addButtonText}>{t('common.add')}</Text>
              )}
            </TouchableOpacity>
          </View>
          {apps.length === 0 ? (
            <EmptyState message={t('split.noApps')} />
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
                      accessibilityLabel={t('split.toggleRule', { name: app.name })}
                      trackColor={{ false: '#374151', true: '#3b82f6' }}
                      thumbColor="#ffffff"
                      disabled={isMutating}
                    />
                    <TouchableOpacity
                      style={styles.removeButton}
                      onPress={() => handleRemoveApp(app)}
                      disabled={isMutating}
                      accessibilityLabel={t('split.removeNamed', { name: app.name })}
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
            title={t('split.domains')}
            subtitle={t('split.domainsSubtitle')}
          />
          <View style={styles.addForm}>
            <TextInput
              style={[styles.input, styles.inputFull]}
              value={newDomain}
              onChangeText={setNewDomain}
              placeholder={t('split.domainPlaceholder')}
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
              accessibilityLabel={t('split.addDomain')}
              accessibilityRole="button"
            >
              {addDomainMutation.isPending ? (
                <ActivityIndicator size="small" color="#ffffff" />
              ) : (
                <Text style={styles.addButtonText}>{t('common.add')}</Text>
              )}
            </TouchableOpacity>
          </View>
          {domains.length === 0 ? (
            <EmptyState message={t('split.noDomains')} />
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
                      accessibilityLabel={t('split.toggleRule', { name: domainEntry.domain })}
                      trackColor={{ false: '#374151', true: '#3b82f6' }}
                      thumbColor="#ffffff"
                      disabled={isMutating}
                    />
                    <TouchableOpacity
                      style={styles.removeButton}
                      onPress={() => handleRemoveDomain(domainEntry)}
                      disabled={isMutating}
                      accessibilityLabel={t('split.removeNamed', { name: domainEntry.domain })}
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
            title={t('split.ipRanges')}
            subtitle={t('split.ipsSubtitle')}
          />
          <View style={styles.addForm}>
            <TextInput
              style={[styles.input, styles.inputFull]}
              value={newIP}
              onChangeText={setNewIP}
              placeholder={t('split.ipPlaceholder')}
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
              accessibilityLabel={t('split.addIP')}
              accessibilityRole="button"
            >
              {addIPMutation.isPending ? (
                <ActivityIndicator size="small" color="#ffffff" />
              ) : (
                <Text style={styles.addButtonText}>{t('common.add')}</Text>
              )}
            </TouchableOpacity>
          </View>
          {ips.length === 0 ? (
            <EmptyState message={t('split.noIPs')} />
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
                      accessibilityLabel={t('split.toggleRule', { name: ipEntry.cidr })}
                      trackColor={{ false: '#374151', true: '#3b82f6' }}
                      thumbColor="#ffffff"
                      disabled={isMutating}
                    />
                    <TouchableOpacity
                      style={styles.removeButton}
                      onPress={() => handleRemoveIP(ipEntry)}
                      disabled={isMutating}
                      accessibilityLabel={t('split.removeNamed', { name: ipEntry.cidr })}
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
          {t('split.footer')}
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
  errorCard: {
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
    borderWidth: 1,
    borderColor: 'rgba(239, 68, 68, 0.3)',
    borderRadius: 12,
    padding: 16,
    marginBottom: 20,
  },
  errorText: {
    color: '#ef4444',
    fontSize: 14,
    fontWeight: '600',
    marginBottom: 4,
  },
  errorDetail: {
    color: '#9ca3af',
    fontSize: 12,
    lineHeight: 18,
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
