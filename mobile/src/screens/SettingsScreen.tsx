import React, { useEffect, useState } from 'react'
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
import { api, ClientConfig, getAPIConfig, setServerUrl, validateServerAddress, extractServerAddress } from '../services/api'
import { useToast } from '../components/Toast'
import { RootStackParamList } from '../navigation/RootNavigator'

type SettingsNavigationProp = NativeStackNavigationProp<RootStackParamList>

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

export function SettingsScreen() {
  const navigation = useNavigation<SettingsNavigationProp>()
  const queryClient = useQueryClient()
  const apiConfig = getAPIConfig()
  const { showToast } = useToast()

  const {
    data: config,
    isLoading,
    error,
  } = useQuery({
    queryKey: ['config'],
    queryFn: api.getConfig,
    refetchInterval: 30000,
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

  const handleSaveServer = async (address: string) => {
    // Validate server address format
    const validationError = validateServerAddress(address)
    if (validationError) {
      showToast(validationError, 'error')
      return
    }

    setIsSavingServer(true)
    try {
      // Update and persist the API base URL
      await setServerUrl(address)

      // Test connection to the new server
      const testResult = await api.testConnection()
      if (!testResult.success) {
        showToast(`Could not connect to server: ${testResult.error}`, 'error')
        setIsSavingServer(false)
        return
      }

      // Update the server config on the backend (may fail if server doesn't support this endpoint)
      try {
        await api.updateConfig({
          server: {
            ...config?.server,
            address,
          },
        } as Partial<ClientConfig>)
      } catch {
        // Ignore errors from updating backend config - the server URL is already saved locally
      }

      // Invalidate queries to refetch with new server
      queryClient.invalidateQueries()

      showToast('Server address saved and connected', 'success')
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Failed to save server address'
      showToast(errorMessage, 'error')
    } finally {
      setIsSavingServer(false)
    }
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

  // Local state for server address input (initialized from API config or backend config)
  const [serverAddress, setServerAddress] = useState(() => {
    // Initialize from current API config
    return extractServerAddress(apiConfig.baseUrl)
  })

  useEffect(() => {
    // Update from backend config if available and local state is still default
    if (config?.server?.address && serverAddress === extractServerAddress(apiConfig.baseUrl)) {
      setServerAddress(config.server.address)
    }
  }, [config?.server?.address])

  if (isLoading) {
    return (
      <View style={styles.loadingContainer}>
        <ActivityIndicator size="large" color="#3b82f6" />
        <Text style={styles.loadingText}>Loading settings...</Text>
      </View>
    )
  }

  if (error) {
    return (
      <View style={styles.loadingContainer}>
        <Text style={styles.errorIcon}>!</Text>
        <Text style={styles.errorText}>Failed to load settings</Text>
        <Text style={styles.errorDetail}>
          {error instanceof Error ? error.message : 'Unknown error'}
        </Text>
      </View>
    )
  }

  const isMutating = updateConfigMutation.isPending

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Connection Settings */}
      <SettingSection title="Connection">
        <SettingItem
          title="Auto-connect"
          description="Connect on app launch"
          disabled={isMutating}
        >
          <Switch
            value={config?.tray?.auto_connect ?? false}
            onValueChange={(value) => handleToggle('auto_connect', value)}
            trackColor={{ false: '#374151', true: '#3b82f6' }}
            thumbColor="#ffffff"
            disabled={isMutating}
            accessibilityLabel="Auto-connect toggle"
            accessibilityHint="When enabled, the app will connect automatically on launch"
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

      {/* Server Settings */}
      <SettingSection title="Server">
        <View style={styles.inputRow}>
          <TextInput
            style={styles.input}
            value={serverAddress}
            onChangeText={setServerAddress}
            placeholder="server:port"
            placeholderTextColor="#6b7280"
            autoCapitalize="none"
            autoCorrect={false}
            editable={!isMutating && !isSavingServer}
            accessibilityLabel="Server address"
            accessibilityHint="Enter the server address in host:port format"
          />
          <TouchableOpacity
            style={[styles.saveButton, (isMutating || isSavingServer) && styles.saveButtonDisabled]}
            onPress={() => handleSaveServer(serverAddress)}
            disabled={isMutating || isSavingServer}
            accessibilityLabel="Save server address"
            accessibilityRole="button"
            accessibilityState={{ disabled: isMutating || isSavingServer }}
          >
            {isSavingServer ? (
              <ActivityIndicator size="small" color="#ffffff" />
            ) : (
              <Text style={styles.saveButtonText}>Save</Text>
            )}
          </TouchableOpacity>
        </View>
      </SettingSection>

      {/* Notifications */}
      <SettingSection title="Notifications">
        <SettingItem
          title="Connection Alerts"
          description="Notify on connect/disconnect"
          disabled={isMutating}
        >
          <Switch
            value={config?.tray?.show_notifications ?? true}
            onValueChange={(value) => handleToggle('show_notifications', value)}
            trackColor={{ false: '#374151', true: '#3b82f6' }}
            thumbColor="#ffffff"
            disabled={isMutating}
            accessibilityLabel="Connection alerts toggle"
            accessibilityHint="When enabled, you will receive notifications on connect and disconnect"
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
              { color: status?.server_status === 'connected' ? '#22c55e' : '#f59e0b' },
            ]}
          >
            {status?.server_status || 'Unknown'}
          </Text>
        </View>
        <View style={styles.aboutItem}>
          <Text style={styles.aboutLabel}>API Endpoint</Text>
          <Text style={styles.aboutValue} numberOfLines={1}>
            {apiConfig.baseUrl}
          </Text>
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
