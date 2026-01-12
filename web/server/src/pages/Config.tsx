import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import { ConfigEditor } from '../components/Config/ConfigEditor'
import type { ServerConfig } from '../api/types'

export function Config() {
  const queryClient = useQueryClient()

  const { data: config, isLoading } = useQuery({
    queryKey: ['config'],
    queryFn: api.getFullConfig,
  })

  const saveMutation = useMutation({
    mutationFn: async ({ config, backup }: { config: ServerConfig; backup: boolean }) => {
      return api.saveConfig({ config, create_backup: backup })
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['config'] })
      if (data.requires_restart) {
        alert('Configuration saved. Server restart required for changes to take effect.')
      } else {
        alert('Configuration saved and reloaded successfully.')
      }
    },
    onError: (error) => {
      alert(`Failed to save configuration: ${error}`)
    },
  })

  const reloadMutation = useMutation({
    mutationFn: api.reloadConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['config'] })
      alert('Configuration reloaded successfully.')
    },
    onError: (error) => {
      alert(`Failed to reload configuration: ${error}`)
    },
  })

  const handleSave = async (config: ServerConfig, backup: boolean) => {
    await saveMutation.mutateAsync({ config, backup })
  }

  const handleReload = async () => {
    await reloadMutation.mutateAsync()
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h2 className="text-2xl font-bold text-white">Configuration</h2>
        <p className="text-bifrost-muted mt-1">
          View and edit server configuration
        </p>
      </div>

      {/* Info Banner */}
      <div className="card bg-gradient-to-r from-bifrost-accent/10 to-transparent border-bifrost-accent/30">
        <div className="flex items-start gap-3">
          <svg
            className="w-5 h-5 text-bifrost-accent flex-shrink-0 mt-0.5"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>
          <div>
            <p className="text-sm text-gray-300">
              Some configuration changes require a server restart to take effect.
              Sections marked with <span className="badge badge-success text-xs ml-1">Hot Reload</span> can be
              updated without restart.
            </p>
          </div>
        </div>
      </div>

      {/* Config Editor */}
      <ConfigEditor
        config={config}
        isLoading={isLoading}
        onSave={handleSave}
        onReload={handleReload}
      />
    </div>
  )
}
