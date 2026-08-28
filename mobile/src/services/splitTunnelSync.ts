import type { AppRule, SplitTunnelConfig } from './api'
import type { StoredSplitTunnelConfig } from './storage'
import { t } from '../i18n'

export interface SplitTunnelRemoteAPI {
  getSplitTunnelRules(): Promise<SplitTunnelConfig>
  setSplitTunnelMode(mode: 'exclude' | 'include'): Promise<unknown>
  addSplitTunnelApp(app: AppRule): Promise<unknown>
  removeSplitTunnelApp(name: string): Promise<unknown>
  addSplitTunnelDomain(domain: string): Promise<unknown>
  removeSplitTunnelDomain(domain: string): Promise<unknown>
  addSplitTunnelIP(cidr: string): Promise<unknown>
  removeSplitTunnelIP(cidr: string): Promise<unknown>
}

function remoteMode(mode: string): 'exclude' | 'include' | null {
  return mode === 'exclude' || mode === 'include' ? mode : null
}

/**
 * Merge remote truth into the locally persisted editor model.
 *
 * Rules present remotely are active (`enabled: true`). Locally remembered
 * rules absent remotely remain visible but disabled, so an operator does not
 * lose a rule they intentionally parked for a later connection. Remote rules
 * added by another client are imported instead of being silently ignored.
 */
export function reconcileSplitTunnelConfig(
  local: StoredSplitTunnelConfig,
  remote: SplitTunnelConfig
): StoredSplitTunnelConfig {
  const remoteApps = remote.apps || []
  const remoteDomains = remote.domains || []
  const remoteIPs = remote.ips || []

  const localAppsByName = new Map(local.apps.map((app) => [app.name, app]))
  const remoteAppNames = new Set(remoteApps.map((app) => app.name))
  const apps = remoteApps.map((app) => {
    const remembered = localAppsByName.get(app.name)
    return {
      name: app.name,
      packageId: app.path || remembered?.packageId || app.name,
      enabled: true,
    }
  })
  apps.push(...local.apps.filter((app) => !remoteAppNames.has(app.name)).map((app) => ({ ...app, enabled: false })))

  const remoteDomainSet = new Set(remoteDomains)
  const domains = remoteDomains.map((domain) => ({ domain, enabled: true }))
  domains.push(...local.domains.filter((item) => !remoteDomainSet.has(item.domain)).map((item) => ({ ...item, enabled: false })))

  const remoteIPSet = new Set(remoteIPs)
  const ips = remoteIPs.map((cidr) => ({ cidr, enabled: true }))
  ips.push(...local.ips.filter((item) => !remoteIPSet.has(item.cidr)).map((item) => ({ ...item, enabled: false })))

  return {
    mode: remoteMode(remote.mode) || local.mode,
    apps,
    domains,
    ips,
  }
}

function appPath(app: AppRule): string {
  return app.path || ''
}

async function operation(label: string, run: () => Promise<unknown>): Promise<void> {
  try {
    await run()
  } catch (error) {
    const detail = error instanceof Error ? error.message : t('split.unknownOperationError')
    throw new Error(`${label}: ${detail}`)
  }
}

/**
 * Replace the remote active rules with the enabled portion of local config.
 *
 * The API only exposes add/remove endpoints, so replacement is implemented as
 * a diff: stale remote rules are removed, missing desired rules are added, and
 * app path changes become remove+add. The first failure aborts and is surfaced;
 * callers must not enable VPN with a partially-synchronised policy.
 */
export async function replaceRemoteSplitTunnelConfig(
  remoteAPI: SplitTunnelRemoteAPI,
  local: StoredSplitTunnelConfig
): Promise<void> {
  const remote = await remoteAPI.getSplitTunnelRules()

  const desiredApps = new Map(
    local.apps
      .filter((app) => app.enabled)
      .map((app) => [app.name, { name: app.name, path: app.packageId || undefined } satisfies AppRule])
  )
  const remoteApps = new Map((remote.apps || []).map((app) => [app.name, app]))

  for (const [name, app] of remoteApps) {
    const desired = desiredApps.get(name)
    if (!desired || appPath(desired) !== appPath(app)) {
      await operation(t('split.syncRemoveApp', { name }), () => remoteAPI.removeSplitTunnelApp(name))
    }
  }
  for (const [name, app] of desiredApps) {
    const existing = remoteApps.get(name)
    if (!existing || appPath(existing) !== appPath(app)) {
      await operation(t('split.syncAddApp', { name }), () => remoteAPI.addSplitTunnelApp(app))
    }
  }

  const desiredDomains = new Set(local.domains.filter((item) => item.enabled).map((item) => item.domain))
  const remoteDomains = new Set(remote.domains || [])
  for (const domain of remoteDomains) {
    if (!desiredDomains.has(domain)) {
      await operation(t('split.syncRemoveDomain', { domain }), () => remoteAPI.removeSplitTunnelDomain(domain))
    }
  }
  for (const domain of desiredDomains) {
    if (!remoteDomains.has(domain)) {
      await operation(t('split.syncAddDomain', { domain }), () => remoteAPI.addSplitTunnelDomain(domain))
    }
  }

  const desiredIPs = new Set(local.ips.filter((item) => item.enabled).map((item) => item.cidr))
  const remoteIPs = new Set(remote.ips || [])
  for (const cidr of remoteIPs) {
    if (!desiredIPs.has(cidr)) {
      await operation(t('split.syncRemoveIP', { cidr }), () => remoteAPI.removeSplitTunnelIP(cidr))
    }
  }
  for (const cidr of desiredIPs) {
    if (!remoteIPs.has(cidr)) {
      await operation(t('split.syncAddIP', { cidr }), () => remoteAPI.addSplitTunnelIP(cidr))
    }
  }

  await operation(t('split.syncMode', { mode: local.mode }), () => remoteAPI.setSplitTunnelMode(local.mode))
}
