import { useState, useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useBackends } from '../hooks/useStats'
import { BackendList } from '../components/Backends/BackendList'
import { AddBackendDialog } from '../components/Backends/AddBackendDialog'
import { TestBackendDialog } from '../components/Backends/TestBackendDialog'
import { ConfirmModal } from '../components/Config/ConfirmModal'
import { useToast } from '../components/Toast'
import { api } from '../api/client'
import type { BackendConfig } from '../api/types'

export function Backends() {
  const { data: backends, isLoading, refetch } = useBackends()
  const queryClient = useQueryClient()
  const { showToast } = useToast()

  // Dialog states
  const [isAddDialogOpen, setIsAddDialogOpen] = useState(false)
  const [editingBackend, setEditingBackend] = useState<BackendConfig | null>(null)
  const [testingBackend, setTestingBackend] = useState<string | null>(null)
  const [deletingBackend, setDeletingBackend] = useState<string | null>(null)
  const [isDeleting, setIsDeleting] = useState(false)

  // Backend configs for editing (fetched from full config)
  const [backendConfigs, setBackendConfigs] = useState<BackendConfig[]>([])

  // Fetch full config to get backend configurations
  useEffect(() => {
    const fetchConfigs = async () => {
      try {
        const config = await api.getFullConfig()
        setBackendConfigs(config.backends || [])
      } catch {
        // Silently fail - configs will be empty
      }
    }
    fetchConfigs()
  }, [backends])

  const existingNames = backends?.map((b) => b.name) || []

  const handleAddBackend = async (config: BackendConfig) => {
    await api.addBackend(config)
    showToast(`Backend "${config.name}" added successfully`, 'success')
    queryClient.invalidateQueries({ queryKey: ['backends'] })
    refetch()
  }

  const handleEditBackend = async (config: BackendConfig) => {
    // Edit is implemented as remove + add since there's no update API
    // First remove the old backend
    await api.removeBackend(config.name)
    // Then add the updated one
    await api.addBackend(config)
    showToast(`Backend "${config.name}" updated successfully`, 'success')
    queryClient.invalidateQueries({ queryKey: ['backends'] })
    refetch()
  }

  const handleDeleteBackend = async (name: string) => {
    setIsDeleting(true)
    try {
      await api.removeBackend(name)
      showToast(`Backend "${name}" deleted successfully`, 'success')
      queryClient.invalidateQueries({ queryKey: ['backends'] })
      refetch()
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to delete backend', 'error')
    } finally {
      setIsDeleting(false)
      setDeletingBackend(null)
    }
  }

  const handleEditClick = (name: string) => {
    const config = backendConfigs.find((b) => b.name === name)
    if (config) {
      setEditingBackend(config)
    } else {
      // If we don't have the config, create a minimal one from runtime data
      const runtime = backends?.find((b) => b.name === name)
      if (runtime) {
        setEditingBackend({
          name: runtime.name,
          type: runtime.type as BackendConfig['type'],
          enabled: true,
          priority: 10,
          weight: 1,
          config: {},
        })
      }
    }
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Backends</h2>
          <p className="text-bifrost-muted mt-1">
            Manage and monitor proxy backend connections
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            className="btn btn-secondary"
            aria-label="Refresh backends"
          >
            <svg
              className="w-4 h-4"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
              aria-hidden="true"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
              />
            </svg>
            Refresh
          </button>
          <button
            onClick={() => setIsAddDialogOpen(true)}
            className="btn btn-primary"
            aria-label="Add backend"
          >
            <svg
              className="w-4 h-4"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
              aria-hidden="true"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M12 4v16m8-8H4"
              />
            </svg>
            Add Backend
          </button>
        </div>
      </div>

      {/* Info Banner */}
      <div className="p-4 bg-bifrost-accent/10 border border-bifrost-accent/30 rounded-lg">
        <div className="flex items-start gap-3">
          <svg className="w-5 h-5 text-bifrost-accent mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p className="text-sm text-gray-300">
            <strong>Runtime vs Persistent:</strong> Backends added here are active immediately but not persisted across restarts.
            To make changes permanent, configure backends in the <a href="/config" className="text-bifrost-accent hover:underline">Configuration</a> page.
          </p>
        </div>
      </div>

      {/* Backend Summary */}
      {backends && backends.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="card bg-gradient-to-br from-bifrost-accent/10 to-transparent">
            <p className="text-sm text-gray-400">Total Backends</p>
            <p className="text-2xl font-bold text-white mt-1">{backends.length}</p>
          </div>
          <div className="card bg-gradient-to-br from-bifrost-success/10 to-transparent">
            <p className="text-sm text-gray-400">Healthy</p>
            <p className="text-2xl font-bold text-bifrost-success mt-1">
              {backends.filter((b) => b.healthy).length}
            </p>
          </div>
          <div className="card bg-gradient-to-br from-bifrost-error/10 to-transparent">
            <p className="text-sm text-gray-400">Unhealthy</p>
            <p className="text-2xl font-bold text-bifrost-error mt-1">
              {backends.filter((b) => !b.healthy).length}
            </p>
          </div>
        </div>
      )}

      {/* Backend List */}
      <BackendList
        backends={backends}
        isLoading={isLoading}
        onEdit={handleEditClick}
        onDelete={(name) => setDeletingBackend(name)}
        onTest={(name) => setTestingBackend(name)}
      />

      {/* Add Backend Dialog */}
      <AddBackendDialog
        isOpen={isAddDialogOpen}
        onClose={() => setIsAddDialogOpen(false)}
        onSave={handleAddBackend}
        existingNames={existingNames}
      />

      {/* Edit Backend Dialog */}
      {editingBackend && (
        <AddBackendDialog
          isOpen={true}
          onClose={() => setEditingBackend(null)}
          onSave={handleEditBackend}
          existingNames={existingNames.filter((n) => n !== editingBackend.name)}
          backend={editingBackend}
        />
      )}

      {/* Test Backend Dialog */}
      {testingBackend && (
        <TestBackendDialog
          isOpen={true}
          onClose={() => setTestingBackend(null)}
          backendName={testingBackend}
        />
      )}

      {/* Delete Confirmation */}
      <ConfirmModal
        isOpen={deletingBackend !== null}
        onClose={() => setDeletingBackend(null)}
        onConfirm={() => deletingBackend && handleDeleteBackend(deletingBackend)}
        title="Delete Backend"
        message={`Are you sure you want to delete the backend "${deletingBackend}"? This action cannot be undone and will stop any active connections through this backend.`}
        confirmLabel={isDeleting ? 'Deleting...' : 'Delete'}
        variant="danger"
      />
    </div>
  )
}
