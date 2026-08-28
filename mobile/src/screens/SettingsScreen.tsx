import React, { useCallback, useState } from 'react'
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  Switch,
  TouchableOpacity,
  TextInput,
  Alert,
  ActivityIndicator,
} from 'react-native'
import { useNavigation } from '@react-navigation/native'
import { NativeStackNavigationProp } from '@react-navigation/native-stack'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  api,
  APIError,
  ClientConfig,
  extractServerAddress,
  getAPIConfig,
  hasAPIToken,
  setAPIToken,
  setServerUrl,
  validateServerAddress,
} from '../services/api'
import { useToast } from '../components/Toast'
import { RootStackParamList } from '../navigation/RootNavigator'
import { t, vpnStatusLabel } from '../i18n'

type SettingsNavigationProp = NativeStackNavigationProp<RootStackParamList>

const CONFIG_REFETCH_INTERVAL = 30000


interface SettingItemProps {
  title: string
  description?: string
  children: React.ReactNode
  disabled?: boolean
}

function SettingItem({ title, description, children, disabled }: SettingItemProps) {
  return (
    <View style={[styles.settingItem, disabled && styles.settingItemDisabled]}>
      <View style={styles.settingInfo}>
        <Text style={[styles.settingTitle, disabled && styles.textDisabled]}>{title}</Text>
        {description && (
          <Text style={[styles.settingDescription, disabled && styles.textDisabled]}>
            {description}
          </Text>
        )}
      </View>
      {children}
    </View>
  )
}

function SettingSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <View style={styles.section}>
      <Text style={styles.sectionTitle}>{title}</Text>
      <View style={styles.sectionContent}>{children}</View>
    </View>
  )
}

interface ClientConnectionSectionProps {
  clientAddress: string
  onChangeClientAddress: (value: string) => void
  onSaveClientAddress: () => void
  isSavingServer: boolean
  tokenInput: string
  onChangeToken: (value: string) => void
  onSaveToken: () => void
  onClearToken: () => void
  tokenConfigured: boolean
  isSavingToken: boolean
  baseUrl: string
  disabled?: boolean
}

/**
 * Address of, and credential for, the Bifrost client this app remote-controls.
 * Rendered both in the normal Settings body and in its error state, so a wrong
 * address or a missing token can always be corrected.
 */
function ClientConnectionSection({
  clientAddress,
  onChangeClientAddress,
  onSaveClientAddress,
  isSavingServer,
  tokenInput,
  onChangeToken,
  onSaveToken,
  onClearToken,
  tokenConfigured,
  isSavingToken,
  baseUrl,
  disabled,
}: ClientConnectionSectionProps) {
  const addressBusy = disabled || isSavingServer
  const tokenBusy = disabled || isSavingToken

  return (
    <SettingSection title={t('settings.clientSection')}>
      <View style={styles.inputRow}>
        <TextInput
          style={styles.input}
          value={clientAddress}
          onChangeText={onChangeClientAddress}
          placeholder={t('settings.addressPlaceholder')}
          placeholderTextColor="#6b7280"
          autoCapitalize="none"
          autoCorrect={false}
          keyboardType="url"
          editable={!addressBusy}
          accessibilityLabel={t('settings.addressLabel')}
          accessibilityHint={t('settings.addressHint')}
        />
        <TouchableOpacity
          style={[styles.saveButton, addressBusy && styles.saveButtonDisabled]}
          onPress={onSaveClientAddress}
          disabled={addressBusy}
          accessibilityLabel={t('settings.saveAddress')}
          accessibilityRole="button"
          accessibilityState={{ disabled: addressBusy }}
        >
          {isSavingServer ? (
            <ActivityIndicator size="small" color="#ffffff" />
          ) : (
            <Text style={styles.saveButtonText}>{t('common.save')}</Text>
          )}
        </TouchableOpacity>
      </View>
      <Text style={styles.inputHint}>
        {t('settings.httpHint')}
      </Text>

      <View style={styles.inputRow}>
        <TextInput
          style={styles.input}
          value={tokenInput}
          onChangeText={onChangeToken}
          placeholder={tokenConfigured ? t('settings.tokenSavedPlaceholder') : t('settings.tokenEmptyPlaceholder')}
          placeholderTextColor="#6b7280"
          autoCapitalize="none"
          autoCorrect={false}
          secureTextEntry={true}
          editable={!tokenBusy}
          accessibilityLabel={t('settings.tokenLabel')}
          accessibilityHint={t('settings.tokenHint')}
        />
        <TouchableOpacity
          style={[styles.saveButton, tokenBusy && styles.saveButtonDisabled]}
          onPress={onSaveToken}
          disabled={tokenBusy}
          accessibilityLabel={t('settings.saveToken')}
          accessibilityRole="button"
          accessibilityState={{ disabled: tokenBusy }}
        >
          {isSavingToken ? (
            <ActivityIndicator size="small" color="#ffffff" />
          ) : (
            <Text style={styles.saveButtonText}>{t('common.save')}</Text>
          )}
        </TouchableOpacity>
      </View>
      <View style={styles.tokenStatusRow}>
        <Text style={styles.inputHint}>
          {tokenConfigured ? t('settings.tokenStored') : t('settings.tokenNotStored')}
        </Text>
        {tokenConfigured && (
          <TouchableOpacity
            onPress={onClearToken}
            disabled={tokenBusy}
            accessibilityLabel={t('settings.clearToken')}
            accessibilityRole="button"
            accessibilityState={{ disabled: tokenBusy }}
          >
            <Text style={styles.clearTokenText}>{t('common.clear')}</Text>
          </TouchableOpacity>
        )}
      </View>

      <View style={styles.aboutItem}>
        <Text style={styles.aboutLabel}>{t('settings.apiEndpoint')}</Text>
        <Text style={styles.aboutValue} numberOfLines={1}>
          {baseUrl}
        </Text>
      </View>
    </SettingSection>
  )
}

export function SettingsScreen() {
  const navigation = useNavigation<SettingsNavigationProp>()
  const queryClient = useQueryClient()
  const apiConfig = getAPIConfig()
  const { showToast } = useToast()

  const {
    data: config,
    isLoading,
    error,
    refetch: refetchConfig,
  } = useQuery({
    queryKey: ['config'],
    queryFn: api.getConfig,
    refetchInterval: CONFIG_REFETCH_INTERVAL,
  })

  const { data: status } = useQuery({
    queryKey: ['status'],
    queryFn: api.getStatus,
  })

  const updateConfigMutation = useMutation({
    mutationFn: (updates: Partial<ClientConfig>) => api.updateConfig(updates),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['config'] })
      showToast(t('settings.saved'), 'success')
    },
    onError: (err) => {
      showToast(err instanceof Error ? err.message : t('settings.updateFailed'), 'error')
    },
  })

  const clearCacheMutation = useMutation({
    mutationFn: api.clearCache,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['status'] })
      showToast(t('settings.cacheCleared'), 'success')
    },
    onError: (err) => {
      showToast(err instanceof Error ? err.message : t('settings.cacheClearFailed'), 'error')
    },
  })

  const handleToggle = (key: keyof NonNullable<ClientConfig['tray']>, value: boolean) => {
    updateConfigMutation.mutate({
      tray: {
        ...config?.tray,
        [key]: value,
      },
    } as Partial<ClientConfig>)
  }

  const handleVPNToggle = (value: boolean) => {
    updateConfigMutation.mutate({
      vpn: {
        ...config?.vpn,
        enabled: value,
      },
    } as Partial<ClientConfig>)
  }

  const [isSavingServer, setIsSavingServer] = useState(false)
  const [isSavingToken, setIsSavingToken] = useState(false)

  // Local state for the client address input. Initialized from the persisted API
  // base URL and thereafter owned by the operator: the backend `server.address`
  // is the upstream proxy server, not the client this app talks to, so it must
  // never overwrite what the user is typing.
  const [clientAddress, setClientAddress] = useState(() =>
    extractServerAddress(apiConfig.baseUrl)
  )

  // Displayed API endpoint. Kept in state so it updates immediately after a
  // save instead of lagging behind the module-level config until a re-render.
  const [baseUrl, setBaseUrl] = useState(apiConfig.baseUrl)

  // Token input. The stored token is never rendered back; an empty field means
  // "leave unchanged" when one is already saved, and the operator clears it
  // explicitly with the Clear button.
  const [tokenInput, setTokenInput] = useState('')
  const [tokenConfigured, setTokenConfigured] = useState(() => hasAPIToken())

  const handleSaveServer = async (address: string) => {
    // Validate the address format (host:port, optionally http:// or https://)
    const validationError = validateServerAddress(address)
    if (validationError) {
      showToast(validationError, 'error')
      return
    }

    setIsSavingServer(true)
    try {
      // Update and persist the API base URL
      await setServerUrl(address)
      const resolvedBaseUrl = getAPIConfig().baseUrl
      setClientAddress(extractServerAddress(resolvedBaseUrl))
      setBaseUrl(resolvedBaseUrl)

      // Test connection to the new client
      const testResult = await api.testConnection()
      if (!testResult.success) {
        showToast(t('settings.clientUnreachable', { error: testResult.error || t('common.unknownError') }), 'error')
        return
      }

      // Invalidate queries to refetch against the new client
      queryClient.invalidateQueries()

      showToast(t('settings.addressConnected'), 'success')
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : t('settings.addressSaveFailed')
      showToast(errorMessage, 'error')
    } finally {
      setIsSavingServer(false)
    }
  }

  const applyToken = useCallback(
    async (token: string, successMessage: string) => {
      setIsSavingToken(true)
      try {
        await setAPIToken(token)
        setTokenConfigured(hasAPIToken())
        setTokenInput('')

        const testResult = await api.testConnection()
        if (!testResult.success) {
          showToast(t('settings.tokenRejected', { error: testResult.error || t('common.unknownError') }), 'error')
          return
        }

        queryClient.invalidateQueries()
        showToast(successMessage, 'success')
      } catch (err) {
        // Never include the token itself in an error message.
        showToast(err instanceof Error ? err.message : t('settings.tokenSaveFailed'), 'error')
      } finally {
        setIsSavingToken(false)
      }
    },
    [queryClient, showToast]
  )

  const handleSaveToken = () => {
    if (!tokenInput.trim()) {
      showToast(t('settings.enterToken'), 'error')
      return
    }
    void applyToken(tokenInput, t('settings.tokenSaved'))
  }

  const handleClearToken = () => {
    Alert.alert(t('settings.clearTokenTitle'), t('settings.clearTokenMessage'), [
      { text: t('common.cancel'), style: 'cancel' },
      {
        text: t('common.clear'),
        style: 'destructive',
        onPress: () => {
          void applyToken('', t('settings.tokenCleared'))
        },
      },
    ])
  }

  const handleClearData = () => {
    Alert.alert(
      t('settings.clearDataTitle'),
      t('settings.clearDataMessage'),
      [
        { text: t('common.cancel'), style: 'cancel' },
        {
          text: t('common.clear'),
          style: 'destructive',
          onPress: () => clearCacheMutation.mutate(),
        },
      ]
    )
  }

  if (isLoading) {
    return (
      <View style={styles.loadingContainer}>
        <ActivityIndicator size="large" color="#3b82f6" />
        <Text style={styles.loadingText}>{t('settings.loading')}</Text>
      </View>
    )
  }

  if (error) {
    const isUnauthorized = error instanceof APIError && error.isUnauthorized
    return (
      <ScrollView style={styles.container} contentContainerStyle={styles.content}>
        <View style={styles.errorPanel} accessible={true} accessibilityRole="alert">
          <Text style={styles.errorIcon}>!</Text>
          <Text style={styles.errorText}>
            {isUnauthorized ? t('settings.authRequired') : t('settings.loadFailed')}
          </Text>
          <Text style={styles.errorDetail}>
            {isUnauthorized
              ? t('settings.authDetail')
              : error instanceof Error
                ? error.message
                : t('common.unknownError')}
          </Text>
          <TouchableOpacity
            style={styles.retryButton}
            onPress={() => {
              void refetchConfig()
            }}
            accessibilityRole="button"
            accessibilityLabel={t('settings.retryLoading')}
          >
            <Text style={styles.retryButtonText}>{t('common.retry')}</Text>
          </TouchableOpacity>
        </View>

        {/* Connection settings stay reachable so the operator can fix the address or token */}
        <ClientConnectionSection
          clientAddress={clientAddress}
          onChangeClientAddress={setClientAddress}
          onSaveClientAddress={() => handleSaveServer(clientAddress)}
          isSavingServer={isSavingServer}
          tokenInput={tokenInput}
          onChangeToken={setTokenInput}
          onSaveToken={handleSaveToken}
          onClearToken={handleClearToken}
          tokenConfigured={tokenConfigured}
          isSavingToken={isSavingToken}
          baseUrl={baseUrl}
        />
      </ScrollView>
    )
  }

  const isMutating = updateConfigMutation.isPending

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Connection Settings */}
      <SettingSection title={t('settings.connection')}>
        <SettingItem
          title={t('settings.autoConnect')}
          description={t('settings.autoConnectDescription')}
          disabled={isMutating}
        >
          <Switch
            value={config?.tray?.auto_connect ?? false}
            onValueChange={(value) => handleToggle('auto_connect', value)}
            trackColor={{ false: '#374151', true: '#3b82f6' }}
            thumbColor="#ffffff"
            disabled={isMutating}
            accessibilityLabel={t('settings.autoConnectLabel')}
            accessibilityHint={t('settings.autoConnectHint')}
            accessibilityState={{ checked: config?.tray?.auto_connect ?? false }}
          />
        </SettingItem>

        <SettingItem
          title={t('settings.vpnMode')}
          description={t('settings.vpnModeDescription')}
          disabled={isMutating}
        >
          <Switch
            value={config?.vpn?.enabled ?? false}
            onValueChange={handleVPNToggle}
            trackColor={{ false: '#374151', true: '#3b82f6' }}
            thumbColor="#ffffff"
            disabled={isMutating}
            accessibilityLabel={t('settings.vpnModeLabel')}
            accessibilityHint={t('settings.vpnModeHint')}
            accessibilityState={{ checked: config?.vpn?.enabled ?? false }}
          />
        </SettingItem>

        <SettingItem
          title={t('nav.splitTunneling')}
          description={t('settings.splitDescription')}
          disabled={isMutating}
        >
          <TouchableOpacity
            style={styles.linkButton}
            onPress={() => navigation.navigate('SplitTunneling')}
            accessibilityLabel={t('settings.configureSplit')}
            accessibilityRole="button"
          >
            <Text style={styles.linkButtonText}>{t('common.configure')}</Text>
          </TouchableOpacity>
        </SettingItem>
      </SettingSection>

      {/* Bifrost client connection */}
      <ClientConnectionSection
        clientAddress={clientAddress}
        onChangeClientAddress={setClientAddress}
        onSaveClientAddress={() => handleSaveServer(clientAddress)}
        isSavingServer={isSavingServer}
        tokenInput={tokenInput}
        onChangeToken={setTokenInput}
        onSaveToken={handleSaveToken}
        onClearToken={handleClearToken}
        tokenConfigured={tokenConfigured}
        isSavingToken={isSavingToken}
        baseUrl={baseUrl}
        disabled={isMutating}
      />

      {/* Notifications */}
      <SettingSection title={t('settings.notifications')}>
        <SettingItem
          title={t('settings.clientNotifications')}
          description={t('settings.clientNotificationsDescription')}
          disabled={isMutating}
        >
          <Switch
            value={config?.tray?.show_notifications ?? true}
            onValueChange={(value) => handleToggle('show_notifications', value)}
            trackColor={{ false: '#374151', true: '#3b82f6' }}
            thumbColor="#ffffff"
            disabled={isMutating}
            accessibilityLabel={t('settings.clientNotificationsLabel')}
            accessibilityHint={t('settings.clientNotificationsHint')}
            accessibilityState={{ checked: config?.tray?.show_notifications ?? true }}
          />
        </SettingItem>
      </SettingSection>

      {/* Data */}
      <SettingSection title={t('settings.dataPrivacy')}>
        <TouchableOpacity
          style={[styles.dangerButton, clearCacheMutation.isPending && styles.dangerButtonDisabled]}
          onPress={handleClearData}
          disabled={clearCacheMutation.isPending}
          accessibilityLabel={t('settings.clearCachedData')}
          accessibilityRole="button"
          accessibilityState={{ disabled: clearCacheMutation.isPending }}
        >
          {clearCacheMutation.isPending ? (
            <ActivityIndicator size="small" color="#ef4444" />
          ) : (
            <Text style={styles.dangerButtonText}>{t('settings.clearCachedData')}</Text>
          )}
        </TouchableOpacity>
      </SettingSection>

      {/* About */}
      <SettingSection title={t('settings.about')}>
        <View style={styles.aboutItem}>
          <Text style={styles.aboutLabel}>{t('stats.version')}</Text>
          <Text style={styles.aboutValue}>{status?.version || '1.0.0'}</Text>
        </View>
        <View style={styles.aboutItem}>
          <Text style={styles.aboutLabel}>{t('settings.serverStatus')}</Text>
          <Text
            style={[
              styles.aboutValue,
              { color: status?.server_connected ? '#22c55e' : '#f59e0b' },
            ]}
          >
            {status ? (status.server_connected ? t('common.connected') : t('common.disconnected')) : t('servers.unknown')}
          </Text>
        </View>
        <View style={styles.aboutItem}>
          <Text style={styles.aboutLabel}>{t('stats.vpnStatus')}</Text>
          <Text style={styles.aboutValue}>{vpnStatusLabel(status?.vpn_status)}</Text>
        </View>
      </SettingSection>

      {/* Footer */}
      <View style={styles.footer}>
        <Text style={styles.footerText}>{t('settings.footer')}</Text>
        <Text style={styles.footerSubtext}>{t('settings.license')}</Text>
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
    marginBottom: 16,
  },
  errorPanel: {
    alignItems: 'center',
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
    borderWidth: 1,
    borderColor: '#ef4444',
    borderRadius: 16,
    padding: 20,
    marginBottom: 24,
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
  inputHint: {
    fontSize: 12,
    color: '#6b7280',
    paddingHorizontal: 12,
    paddingBottom: 12,
  },
  tokenStatusRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingRight: 12,
  },
  clearTokenText: {
    fontSize: 14,
    fontWeight: '600',
    color: '#ef4444',
    paddingBottom: 12,
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
  sectionContent: {
    backgroundColor: '#111827',
    borderRadius: 16,
    borderWidth: 1,
    borderColor: '#1f2937',
    overflow: 'hidden',
  },
  settingItem: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#1f2937',
  },
  settingItemDisabled: {
    opacity: 0.6,
  },
  settingInfo: {
    flex: 1,
    marginRight: 12,
  },
  settingTitle: {
    fontSize: 16,
    fontWeight: '500',
    color: '#f9fafb',
    marginBottom: 2,
  },
  settingDescription: {
    fontSize: 13,
    color: '#6b7280',
  },
  textDisabled: {
    color: '#4b5563',
  },
  linkButton: {
    backgroundColor: '#1f2937',
    paddingHorizontal: 12,
    paddingVertical: 6,
    borderRadius: 6,
  },
  linkButtonText: {
    color: '#3b82f6',
    fontSize: 14,
    fontWeight: '500',
  },
  inputRow: {
    flexDirection: 'row',
    padding: 12,
    gap: 12,
  },
  input: {
    flex: 1,
    backgroundColor: '#0a0e17',
    borderWidth: 1,
    borderColor: '#1f2937',
    borderRadius: 8,
    padding: 12,
    color: '#f9fafb',
    fontFamily: 'monospace',
    fontSize: 14,
  },
  saveButton: {
    backgroundColor: '#3b82f6',
    paddingHorizontal: 20,
    paddingVertical: 12,
    borderRadius: 8,
    justifyContent: 'center',
    minWidth: 70,
    alignItems: 'center',
  },
  saveButtonDisabled: {
    opacity: 0.6,
  },
  saveButtonText: {
    color: '#ffffff',
    fontWeight: '600',
  },
  dangerButton: {
    padding: 16,
    alignItems: 'center',
  },
  dangerButtonDisabled: {
    opacity: 0.6,
  },
  dangerButtonText: {
    color: '#ef4444',
    fontSize: 16,
    fontWeight: '500',
  },
  aboutItem: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    padding: 16,
    borderBottomWidth: 1,
    borderBottomColor: '#1f2937',
  },
  aboutLabel: {
    fontSize: 16,
    color: '#f9fafb',
  },
  aboutValue: {
    fontSize: 16,
    color: '#6b7280',
    fontFamily: 'monospace',
    maxWidth: '60%',
  },
  footer: {
    alignItems: 'center',
    marginTop: 20,
  },
  footerText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#6b7280',
  },
  footerSubtext: {
    fontSize: 12,
    color: '#4b5563',
    marginTop: 4,
  },
})
