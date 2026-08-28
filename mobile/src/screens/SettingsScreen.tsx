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

type SettingsNavigationProp = NativeStackNavigationProp<RootStackParamList>

const CONFIG_REFETCH_INTERVAL = 30000

/** Placeholder shown instead of a stored token, which is never displayed. */
const TOKEN_PLACEHOLDER_SAVED = 'Token saved - enter a new one to replace'
const TOKEN_PLACEHOLDER_EMPTY = 'API token (leave empty if none)'

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
    <SettingSection title="Bifrost Client">
      <View style={styles.inputRow}>
        <TextInput
          style={styles.input}
          value={clientAddress}
          onChangeText={onChangeClientAddress}
          placeholder="host:port or https://host:port"
          placeholderTextColor="#6b7280"
          autoCapitalize="none"
          autoCorrect={false}
          keyboardType="url"
          editable={!addressBusy}
          accessibilityLabel="Bifrost client address"
          accessibilityHint="Enter host and port, optionally prefixed with http:// or https://"
        />
        <TouchableOpacity
          style={[styles.saveButton, addressBusy && styles.saveButtonDisabled]}
          onPress={onSaveClientAddress}
          disabled={addressBusy}
          accessibilityLabel="Save client address"
          accessibilityRole="button"
          accessibilityState={{ disabled: addressBusy }}
        >
          {isSavingServer ? (
            <ActivityIndicator size="small" color="#ffffff" />
          ) : (
            <Text style={styles.saveButtonText}>Save</Text>
          )}
        </TouchableOpacity>
      </View>
      <Text style={styles.inputHint}>
        Plain host:port uses HTTP. Prefix with https:// for a TLS-terminated client.
      </Text>

      <View style={styles.inputRow}>
        <TextInput
          style={styles.input}
          value={tokenInput}
          onChangeText={onChangeToken}
          placeholder={tokenConfigured ? TOKEN_PLACEHOLDER_SAVED : TOKEN_PLACEHOLDER_EMPTY}
          placeholderTextColor="#6b7280"
          autoCapitalize="none"
          autoCorrect={false}
          secureTextEntry={true}
          editable={!tokenBusy}
          accessibilityLabel="API token"
          accessibilityHint="Bearer token required when the client has api.token configured"
        />
        <TouchableOpacity
          style={[styles.saveButton, tokenBusy && styles.saveButtonDisabled]}
          onPress={onSaveToken}
          disabled={tokenBusy}
          accessibilityLabel="Save API token"
          accessibilityRole="button"
          accessibilityState={{ disabled: tokenBusy }}
        >
          {isSavingToken ? (
            <ActivityIndicator size="small" color="#ffffff" />
          ) : (
            <Text style={styles.saveButtonText}>Save</Text>
          )}
        </TouchableOpacity>
      </View>
      <View style={styles.tokenStatusRow}>
        <Text style={styles.inputHint}>
          {tokenConfigured ? 'A token is stored on this device.' : 'No token stored.'}
        </Text>
        {tokenConfigured && (
          <TouchableOpacity
            onPress={onClearToken}
            disabled={tokenBusy}
            accessibilityLabel="Clear stored API token"
            accessibilityRole="button"
            accessibilityState={{ disabled: tokenBusy }}
          >
            <Text style={styles.clearTokenText}>Clear</Text>
          </TouchableOpacity>
        )}
      </View>

      <View style={styles.aboutItem}>
        <Text style={styles.aboutLabel}>API Endpoint</Text>
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
      showToast('Settings saved', 'success')
    },
    onError: (err) => {
      showToast(err instanceof Error ? err.message : 'Failed to update settings', 'error')
    },
  })

  const clearCacheMutation = useMutation({
    mutationFn: api.clearCache,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['status'] })
      showToast('Cache cleared successfully', 'success')
    },
    onError: (err) => {
      showToast(err instanceof Error ? err.message : 'Failed to clear cache', 'error')
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
        showToast(`Could not connect to client: ${testResult.error}`, 'error')
        return
      }

      // Invalidate queries to refetch against the new client
      queryClient.invalidateQueries()

      showToast('Client address saved and connected', 'success')
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to save client address'
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
          showToast(`Saved, but the client rejected it: ${testResult.error}`, 'error')
          return
        }

        queryClient.invalidateQueries()
        showToast(successMessage, 'success')
      } catch (err) {
        // Never include the token itself in an error message.
        showToast(err instanceof Error ? err.message : 'Failed to save API token', 'error')
      } finally {
        setIsSavingToken(false)
      }
    },
    [queryClient, showToast]
  )

  const handleSaveToken = () => {
    if (!tokenInput.trim()) {
      showToast('Enter a token, or use Clear to remove the stored one', 'error')
      return
    }
    void applyToken(tokenInput, 'API token saved')
  }

  const handleClearToken = () => {
    Alert.alert('Clear API Token', 'Remove the stored API token from this device?', [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Clear',
        style: 'destructive',
        onPress: () => {
          void applyToken('', 'API token cleared')
        },
      },
    ])
  }

  const handleClearData = () => {
    Alert.alert(
      'Clear Data',
      'Are you sure you want to clear all cached data?',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Clear',
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
        <Text style={styles.loadingText}>Loading settings...</Text>
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
            {isUnauthorized ? 'Authentication required' : 'Failed to load settings'}
          </Text>
          <Text style={styles.errorDetail}>
            {isUnauthorized
              ? 'The Bifrost client rejected the request. Enter a valid API token below.'
              : error instanceof Error
                ? error.message
                : 'Unknown error'}
          </Text>
          <TouchableOpacity
            style={styles.retryButton}
            onPress={() => {
              void refetchConfig()
            }}
            accessibilityRole="button"
            accessibilityLabel="Retry loading settings"
          >
            <Text style={styles.retryButtonText}>Retry</Text>
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
      <SettingSection title="Connection">
        <SettingItem
          title="Client auto-connect"
          description="Connect when the Bifrost client starts (remote setting)"
          disabled={isMutating}
        >
          <Switch
            value={config?.tray?.auto_connect ?? false}
            onValueChange={(value) => handleToggle('auto_connect', value)}
            trackColor={{ false: '#374151', true: '#3b82f6' }}
            thumbColor="#ffffff"
            disabled={isMutating}
            accessibilityLabel="Client auto-connect toggle"
            accessibilityHint="When enabled, the Bifrost client connects automatically on startup"
            accessibilityState={{ checked: config?.tray?.auto_connect ?? false }}
          />
        </SettingItem>

        <SettingItem
          title="VPN Mode"
          description="Route all traffic through VPN tunnel"
          disabled={isMutating}
        >
          <Switch
            value={config?.vpn?.enabled ?? false}
            onValueChange={handleVPNToggle}
            trackColor={{ false: '#374151', true: '#3b82f6' }}
            thumbColor="#ffffff"
            disabled={isMutating}
            accessibilityLabel="VPN mode toggle"
            accessibilityHint="When enabled, all traffic will be routed through VPN tunnel"
            accessibilityState={{ checked: config?.vpn?.enabled ?? false }}
          />
        </SettingItem>

        <SettingItem
          title="Split Tunneling"
          description="Exclude certain apps from VPN"
          disabled={isMutating}
        >
          <TouchableOpacity
            style={styles.linkButton}
            onPress={() => navigation.navigate('SplitTunneling')}
            accessibilityLabel="Configure split tunneling"
            accessibilityRole="button"
          >
            <Text style={styles.linkButtonText}>Configure</Text>
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
      <SettingSection title="Notifications">
        <SettingItem
          title="Client Notifications"
          description="Desktop notifications on the Bifrost client (remote setting)"
          disabled={isMutating}
        >
          <Switch
            value={config?.tray?.show_notifications ?? true}
            onValueChange={(value) => handleToggle('show_notifications', value)}
            trackColor={{ false: '#374151', true: '#3b82f6' }}
            thumbColor="#ffffff"
            disabled={isMutating}
            accessibilityLabel="Client notifications toggle"
            accessibilityHint="When enabled, the Bifrost client shows desktop notifications on connect and disconnect"
            accessibilityState={{ checked: config?.tray?.show_notifications ?? true }}
          />
        </SettingItem>
      </SettingSection>

      {/* Data */}
      <SettingSection title="Data & Privacy">
        <TouchableOpacity
          style={[styles.dangerButton, clearCacheMutation.isPending && styles.dangerButtonDisabled]}
          onPress={handleClearData}
          disabled={clearCacheMutation.isPending}
          accessibilityLabel="Clear cached data"
          accessibilityRole="button"
          accessibilityState={{ disabled: clearCacheMutation.isPending }}
        >
          {clearCacheMutation.isPending ? (
            <ActivityIndicator size="small" color="#ef4444" />
          ) : (
            <Text style={styles.dangerButtonText}>Clear Cached Data</Text>
          )}
        </TouchableOpacity>
      </SettingSection>

      {/* About */}
      <SettingSection title="About">
        <View style={styles.aboutItem}>
          <Text style={styles.aboutLabel}>Version</Text>
          <Text style={styles.aboutValue}>{status?.version || '1.0.0'}</Text>
        </View>
        <View style={styles.aboutItem}>
          <Text style={styles.aboutLabel}>Server Status</Text>
          <Text
            style={[
              styles.aboutValue,
              { color: status?.server_connected ? '#22c55e' : '#f59e0b' },
            ]}
          >
            {status ? (status.server_connected ? 'Connected' : 'Disconnected') : 'Unknown'}
          </Text>
        </View>
        <View style={styles.aboutItem}>
          <Text style={styles.aboutLabel}>VPN Status</Text>
          <Text style={styles.aboutValue}>{status?.vpn_status || 'Unknown'}</Text>
        </View>
      </SettingSection>

      {/* Footer */}
      <View style={styles.footer}>
        <Text style={styles.footerText}>Bifrost VPN</Text>
        <Text style={styles.footerSubtext}>MIT License</Text>
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
