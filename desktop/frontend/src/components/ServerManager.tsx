import { useState, useEffect, useRef, useCallback } from 'react';
import { ServerInfo, ServerConfig } from '../hooks/useClient';
import { getStatusColor, getStatusLabel, validateServerAddress } from '../utils/status';

interface ServerManagerProps {
  servers: ServerInfo[];
  currentServer: string;
  onSelect: (name: string) => void;
  onAdd: (server: ServerConfig) => Promise<void>;
  onUpdate: (originalName: string, server: ServerConfig) => Promise<void>;
  onDelete: (name: string) => Promise<void>;
  onSetDefault: (name: string) => Promise<void>;
  disabled?: boolean;
}

interface ServerDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (server: ServerConfig) => Promise<void>;
  server?: ServerInfo;
  title: string;
}

function ServerDialog({ isOpen, onClose, onSave, server, title }: ServerDialogProps) {
  const [name, setName] = useState(server?.name || '');
  const [address, setAddress] = useState(server?.address || '');
  const [protocol, setProtocol] = useState(server?.protocol || 'http');
  const [username, setUsername] = useState(server?.username || '');
  const [password, setPassword] = useState(server?.password || '');
  const [isDefault, setIsDefault] = useState(server?.is_default || false);
  const [errors, setErrors] = useState<{ name?: string; address?: string }>({});
  const [saving, setSaving] = useState(false);
  const dialogRef = useRef<HTMLDivElement>(null);
  const firstInputRef = useRef<HTMLInputElement>(null);

  // Handle Escape key to close dialog
  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      onClose();
    }
  }, [onClose]);

  useEffect(() => {
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
      // Focus first input when dialog opens
      firstInputRef.current?.focus();
      return () => document.removeEventListener('keydown', handleKeyDown);
    }
  }, [isOpen, handleKeyDown]);

  if (!isOpen) return null;

  const validate = () => {
    const newErrors: { name?: string; address?: string } = {};

    if (!name.trim()) {
      newErrors.name = 'Server name is required';
    }

    const addressError = validateServerAddress(address);
    if (addressError) {
      newErrors.address = addressError;
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSave = async () => {
    if (!validate()) return;

    setSaving(true);
    try {
      await onSave({
        name: name.trim(),
        address: address.trim(),
        protocol,
        username: username.trim() || undefined,
        password: password.trim() || undefined,
        is_default: isDefault,
      });
      onClose();
    } catch {
      // Error is handled by the parent
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/50 z-40"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Dialog */}
      <div
        className="fixed inset-0 z-50 flex items-center justify-center p-4"
        role="dialog"
        aria-modal="true"
        aria-labelledby="dialog-title"
      >
        <div ref={dialogRef} className="bg-bifrost-card border border-bifrost-border rounded-xl shadow-xl w-full max-w-md">
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-bifrost-border">
            <h2 id="dialog-title" className="text-lg font-semibold text-bifrost-text">
              {title}
            </h2>
            <button
              onClick={onClose}
              className="p-1 text-bifrost-text-muted hover:text-bifrost-text rounded-lg transition-colors"
              aria-label="Close dialog"
            >
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          {/* Body */}
          <div className="p-4 space-y-4">
            {/* Server Name */}
            <div>
              <label htmlFor="server-name" className="block text-sm font-medium text-bifrost-text mb-1">
                Server Name
              </label>
              <input
                ref={firstInputRef}
                id="server-name"
                type="text"
                value={name}
                onChange={(e) => {
                  setName(e.target.value);
                  if (errors.name) setErrors({ ...errors, name: undefined });
                }}
                placeholder="My Server"
                className={`w-full px-3 py-2 text-sm bg-bifrost-bg border rounded-lg text-bifrost-text placeholder-bifrost-text-muted focus:outline-none focus:ring-1 focus:ring-bifrost-accent ${
                  errors.name ? 'border-bifrost-error' : 'border-bifrost-border'
                }`}
                aria-invalid={!!errors.name}
                aria-describedby={errors.name ? 'name-error' : undefined}
              />
              {errors.name && (
                <p id="name-error" className="text-xs text-bifrost-error mt-1">
                  {errors.name}
                </p>
              )}
            </div>

            {/* Server Address */}
            <div>
              <label htmlFor="server-address" className="block text-sm font-medium text-bifrost-text mb-1">
                Server Address
              </label>
              <input
                id="server-address"
                type="text"
                value={address}
                onChange={(e) => {
                  setAddress(e.target.value);
                  if (errors.address) setErrors({ ...errors, address: undefined });
                }}
                placeholder="bifrost.example.com:8080"
                className={`w-full px-3 py-2 text-sm bg-bifrost-bg border rounded-lg text-bifrost-text placeholder-bifrost-text-muted focus:outline-none focus:ring-1 focus:ring-bifrost-accent ${
                  errors.address ? 'border-bifrost-error' : 'border-bifrost-border'
                }`}
                aria-invalid={!!errors.address}
                aria-describedby={errors.address ? 'address-error' : undefined}
              />
              {errors.address && (
                <p id="address-error" className="text-xs text-bifrost-error mt-1">
                  {errors.address}
                </p>
              )}
            </div>

            {/* Protocol */}
            <div>
              <label htmlFor="server-protocol" className="block text-sm font-medium text-bifrost-text mb-1">
                Protocol
              </label>
              <select
                id="server-protocol"
                value={protocol}
                onChange={(e) => setProtocol(e.target.value)}
                className="w-full px-3 py-2 text-sm bg-bifrost-bg border border-bifrost-border rounded-lg text-bifrost-text focus:outline-none focus:ring-1 focus:ring-bifrost-accent"
              >
                <option value="http">HTTP</option>
                <option value="socks5">SOCKS5</option>
              </select>
            </div>

            {/* Authentication (collapsible) */}
            <details className="group">
              <summary className="cursor-pointer text-sm font-medium text-bifrost-text-muted hover:text-bifrost-text flex items-center gap-1">
                <svg className="w-4 h-4 transition-transform group-open:rotate-90" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5l7 7-7 7" />
                </svg>
                Authentication (optional)
              </summary>
              <div className="mt-3 space-y-3 pl-5">
                <div>
                  <label htmlFor="server-username" className="block text-xs font-medium text-bifrost-text-muted mb-1">
                    Username
                  </label>
                  <input
                    id="server-username"
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="Optional"
                    className="w-full px-3 py-1.5 text-sm bg-bifrost-bg border border-bifrost-border rounded-md text-bifrost-text placeholder-bifrost-text-muted focus:outline-none focus:ring-1 focus:ring-bifrost-accent"
                  />
                </div>
                <div>
                  <label htmlFor="server-password" className="block text-xs font-medium text-bifrost-text-muted mb-1">
                    Password
                  </label>
                  <input
                    id="server-password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Optional"
                    className="w-full px-3 py-1.5 text-sm bg-bifrost-bg border border-bifrost-border rounded-md text-bifrost-text placeholder-bifrost-text-muted focus:outline-none focus:ring-1 focus:ring-bifrost-accent"
                  />
                </div>
              </div>
            </details>

            {/* Set as Default */}
            <div className="flex items-center gap-2">
              <input
                id="server-default"
                type="checkbox"
                checked={isDefault}
                onChange={(e) => setIsDefault(e.target.checked)}
                className="w-4 h-4 rounded border-bifrost-border text-bifrost-accent focus:ring-bifrost-accent bg-bifrost-bg"
              />
              <label htmlFor="server-default" className="text-sm text-bifrost-text">
                Set as default server
              </label>
            </div>
          </div>

          {/* Footer */}
          <div className="flex justify-end gap-2 px-4 py-3 border-t border-bifrost-border">
            <button
              onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-bifrost-text-muted hover:text-bifrost-text rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleSave}
              disabled={saving}
              className="px-4 py-2 text-sm font-medium bg-bifrost-accent text-white rounded-lg hover:bg-bifrost-accent/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {saving ? 'Saving...' : 'Save'}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}

interface DeleteConfirmDialogProps {
  isOpen: boolean;
  serverName: string;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}

function DeleteConfirmDialog({ isOpen, serverName, onClose, onConfirm }: DeleteConfirmDialogProps) {
  const [deleting, setDeleting] = useState(false);
  const cancelButtonRef = useRef<HTMLButtonElement>(null);

  // Handle Escape key to close dialog
  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      onClose();
    }
  }, [onClose]);

  useEffect(() => {
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
      // Focus cancel button when dialog opens (safer option for destructive dialogs)
      cancelButtonRef.current?.focus();
      return () => document.removeEventListener('keydown', handleKeyDown);
    }
  }, [isOpen, handleKeyDown]);

  if (!isOpen) return null;

  const handleDelete = async () => {
    setDeleting(true);
    try {
      await onConfirm();
      onClose();
    } catch {
      // Error handled by parent
    } finally {
      setDeleting(false);
    }
  };

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/50 z-40"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Dialog */}
      <div
        className="fixed inset-0 z-50 flex items-center justify-center p-4"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="delete-dialog-title"
        aria-describedby="delete-dialog-description"
      >
        <div className="bg-bifrost-card border border-bifrost-border rounded-xl shadow-xl w-full max-w-sm">
          <div className="p-4">
            <h2 id="delete-dialog-title" className="text-lg font-semibold text-bifrost-text mb-2">
              Delete Server
            </h2>
            <p id="delete-dialog-description" className="text-sm text-bifrost-text-muted">
              Are you sure you want to delete <span className="font-medium text-bifrost-text">{serverName}</span>? This action cannot be undone.
            </p>
          </div>
          <div className="flex justify-end gap-2 px-4 py-3 border-t border-bifrost-border">
            <button
              ref={cancelButtonRef}
              onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-bifrost-text-muted hover:text-bifrost-text rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleDelete}
              disabled={deleting}
              className="px-4 py-2 text-sm font-medium bg-bifrost-error text-white rounded-lg hover:bg-bifrost-error/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {deleting ? 'Deleting...' : 'Delete'}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}

export function ServerManager({
  servers,
  currentServer,
  onSelect,
  onAdd,
  onUpdate,
  onDelete,
  onSetDefault,
  disabled,
}: ServerManagerProps) {
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [editingServer, setEditingServer] = useState<ServerInfo | null>(null);
  const [deletingServer, setDeletingServer] = useState<string | null>(null);

  const handleAdd = async (server: ServerConfig) => {
    await onAdd(server);
  };

  const handleEdit = async (server: ServerConfig) => {
    if (editingServer) {
      await onUpdate(editingServer.name, server);
    }
  };

  const handleDelete = async () => {
    if (deletingServer) {
      await onDelete(deletingServer);
    }
  };

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-bifrost-text">Servers</h3>
        <button
          onClick={() => setShowAddDialog(true)}
          disabled={disabled}
          className="p-1.5 text-bifrost-accent hover:bg-bifrost-accent/10 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          aria-label="Add server"
        >
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 4v16m8-8H4" />
          </svg>
        </button>
      </div>

      {/* Server List */}
      {servers.length === 0 ? (
        <div className="text-center py-6">
          <svg className="w-12 h-12 mx-auto text-bifrost-text-muted mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
          </svg>
          <p className="text-sm text-bifrost-text-muted mb-3">No servers configured</p>
          <button
            onClick={() => setShowAddDialog(true)}
            disabled={disabled}
            className="px-4 py-2 text-sm font-medium bg-bifrost-accent text-white rounded-lg hover:bg-bifrost-accent/90 transition-colors disabled:opacity-50"
          >
            Add Server
          </button>
        </div>
      ) : (
        <div className="space-y-2">
          {servers.map((server) => (
            <div
              key={server.name}
              className={`group flex items-center justify-between p-3 rounded-lg border transition-colors ${
                server.name === currentServer
                  ? 'bg-bifrost-accent/10 border-bifrost-accent'
                  : 'bg-bifrost-bg border-bifrost-border hover:border-bifrost-accent/50'
              }`}
            >
              {/* Server Info */}
              <button
                onClick={() => !disabled && onSelect(server.name)}
                disabled={disabled}
                className="flex-1 flex items-center gap-3 text-left disabled:cursor-not-allowed"
                aria-label={`Select server ${server.name}`}
              >
                <div className="flex items-center gap-1.5 min-w-[70px]">
                  <span className={`w-2 h-2 rounded-full ${getStatusColor(server.status)}`} aria-hidden="true" />
                  <span className="text-[10px] text-bifrost-text-muted uppercase">
                    {getStatusLabel(server.status)}
                  </span>
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-medium text-bifrost-text">{server.name}</p>
                    {server.is_default && (
                      <span className="text-[10px] px-1.5 py-0.5 bg-bifrost-accent/20 text-bifrost-accent rounded">
                        Default
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-bifrost-text-muted">
                    {server.address} ({server.protocol.toUpperCase()})
                  </p>
                </div>
              </button>

              {/* Actions */}
              <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                {!server.is_default && (
                  <button
                    onClick={() => onSetDefault(server.name)}
                    disabled={disabled}
                    className="p-1.5 text-bifrost-text-muted hover:text-bifrost-accent rounded transition-colors disabled:opacity-50"
                    aria-label={`Set ${server.name} as default`}
                    title="Set as default"
                  >
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
                    </svg>
                  </button>
                )}
                <button
                  onClick={() => setEditingServer(server)}
                  disabled={disabled}
                  className="p-1.5 text-bifrost-text-muted hover:text-bifrost-text rounded transition-colors disabled:opacity-50"
                  aria-label={`Edit ${server.name}`}
                  title="Edit"
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                  </svg>
                </button>
                <button
                  onClick={() => setDeletingServer(server.name)}
                  disabled={disabled}
                  className="p-1.5 text-bifrost-text-muted hover:text-bifrost-error rounded transition-colors disabled:opacity-50"
                  aria-label={`Delete ${server.name}`}
                  title="Delete"
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Add Server Dialog */}
      <ServerDialog
        isOpen={showAddDialog}
        onClose={() => setShowAddDialog(false)}
        onSave={handleAdd}
        title="Add Server"
      />

      {/* Edit Server Dialog */}
      <ServerDialog
        isOpen={editingServer !== null}
        onClose={() => setEditingServer(null)}
        onSave={handleEdit}
        server={editingServer || undefined}
        title="Edit Server"
      />

      {/* Delete Confirmation Dialog */}
      <DeleteConfirmDialog
        isOpen={deletingServer !== null}
        serverName={deletingServer || ''}
        onClose={() => setDeletingServer(null)}
        onConfirm={handleDelete}
      />
    </div>
  );
}
