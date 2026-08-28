/**
 * Single source of truth for the server config sections rendered by the
 * configuration editor.
 *
 * Every entry ties together the four identities a section has, which previously
 * lived in three places and drifted apart:
 *
 *  - `key`     the name the server uses in `changed_sections` / `/config/meta`
 *              and the `yaml`/`json` key of the section (see the Section*
 *              constants in `internal/api/server/config_handlers.go`).
 *  - `domId`   the scroll anchor. Derived from `key`, never from the heading, so
 *              renaming a heading cannot silently break the sidebar link (the
 *              "Health Check" link used to point at a non-existent id because
 *              the heading had been renamed to "Global Health Checks").
 *  - `title`   the heading rendered by the section itself.
 *  - `label`   the short form used in the sidebar and in dirty-state chips.
 *
 * `hotReloadable` mirrors the server's `hotReloadableSections` map. It is only a
 * fallback: at runtime the editor prefers the live `/config/meta` response so
 * the UI cannot claim a section hot-reloads when the server disagrees.
 */

import type { ServerConfig } from '../../api/types'

export const CONFIG_SECTION_KEYS = [
  'server',
  'backends',
  'routes',
  'auth',
  'rate_limit',
  'access_control',
  'access_log',
  'metrics',
  'logging',
  'web_ui',
  'api',
  'health_check',
  'auto_update',
  'cache',
  'network',
  'session',
  'mitm',
  'mesh',
] as const

export type ConfigSectionKey = (typeof CONFIG_SECTION_KEYS)[number]

/**
 * Compile-time guarantee that the section keys and the ServerConfig fields are
 * exactly the same set. Either a key that is not a config field, or a config
 * field with no section, would leave part of the schema unreachable from the
 * editor — which is how `network`, `session` and `mitm` were once YAML-only.
 */
export type ConfigSectionKeysMatchServerConfig =
  [ConfigSectionKey] extends [keyof ServerConfig]
    ? [keyof ServerConfig] extends [ConfigSectionKey]
      ? true
      : { error: 'ServerConfig field has no CONFIG_SECTIONS entry'; missing: Exclude<keyof ServerConfig, ConfigSectionKey> }
    : { error: 'CONFIG_SECTION_KEYS entry is not a ServerConfig field'; unknownKeys: Exclude<ConfigSectionKey, keyof ServerConfig> }

// Fails to compile unless the two sets match exactly.
export const CONFIG_SECTIONS_MATCH_SCHEMA: ConfigSectionKeysMatchServerConfig = true

/**
 * Section groups, in display order. Grouping keeps the 17-section editor
 * navigable: an operator looking for an IP blocklist looks under "Security &
 * Access" rather than scanning one flat 17-item list.
 */
export const CONFIG_SECTION_GROUPS = [
  'Core',
  'Security & Access',
  'Traffic & Performance',
  'Observability',
  'Platform',
] as const

export type ConfigSectionGroup = (typeof CONFIG_SECTION_GROUPS)[number]

export interface ConfigSectionMeta {
  key: ConfigSectionKey
  domId: string
  title: string
  label: string
  group: ConfigSectionGroup
  /** Fallback hot-reloadability; the live `/config/meta` response wins. */
  hotReloadable: boolean
  /** Extra terms matched by the sidebar filter. */
  keywords: string[]
}

/** Builds the scroll-anchor id for a section. */
export function sectionDomId(key: ConfigSectionKey): string {
  return `config-section-${key.replace(/_/g, '-')}`
}

function meta(
  key: ConfigSectionKey,
  title: string,
  label: string,
  group: ConfigSectionGroup,
  hotReloadable: boolean,
  keywords: string[]
): ConfigSectionMeta {
  return { key, domId: sectionDomId(key), title, label, group, hotReloadable, keywords }
}

export const CONFIG_SECTIONS: ConfigSectionMeta[] = [
  meta('server', 'Server Settings', 'Server', 'Core', false, [
    'http', 'socks5', 'listen', 'tls', 'timeout', 'listener', 'mtls', 'certificate',
  ]),
  meta('backends', 'Backends', 'Backends', 'Core', false, [
    'backend', 'wireguard', 'openvpn', 'proxy', 'vpn', 'socks5', 'direct', 'weight',
  ]),
  meta('routes', 'Routes', 'Routes', 'Core', true, [
    'route', 'domain', 'load balance', 'weighted', 'round robin', 'priority',
  ]),

  meta('auth', 'Authentication', 'Authentication', 'Security & Access', false, [
    'auth', 'native', 'ldap', 'oauth', 'jwt', 'mtls', 'kerberos', 'negotiate',
    'spnego', 'user', 'password', 'api key', 'totp', 'mfa',
  ]),
  meta('access_control', 'Access Control', 'Access Control', 'Security & Access', true, [
    'whitelist', 'blacklist', 'ip', 'acl', 'allow', 'deny', 'cidr', 'block',
  ]),
  meta('mitm', 'HTTPS Interception (MITM)', 'MITM', 'Security & Access', false, [
    'mitm', 'https', 'interception', 'ca', 'debug', 'decrypt', 'certificate',
  ]),

  meta('rate_limit', 'Rate Limiting', 'Rate Limit', 'Traffic & Performance', true, [
    'rate', 'limit', 'throttle', 'bandwidth', 'burst', 'quota',
  ]),
  meta('cache', 'Cache', 'Cache', 'Traffic & Performance', true, [
    'cache', 'memory', 'disk', 'ttl', 'evict', 'tiered', 'purge',
  ]),
  meta('health_check', 'Global Health Checks', 'Health Checks', 'Traffic & Performance', false, [
    'health', 'check', 'tcp', 'ping', 'threshold', 'https', 'probe',
  ]),
  meta('network', 'Network', 'Network', 'Traffic & Performance', false, [
    'network', 'ipv6', 'keepalive', 'dial', 'connections', 'max connections',
  ]),

  meta('access_log', 'Access Logging', 'Access Log', 'Observability', false, [
    'access', 'log', 'format', 'apache', 'audit',
  ]),
  meta('metrics', 'Prometheus Metrics', 'Metrics', 'Observability', false, [
    'prometheus', 'metrics', 'monitoring', 'scrape', 'grafana',
  ]),
  meta('logging', 'Application Logging', 'Logging', 'Observability', false, [
    'log', 'level', 'debug', 'format', 'rotation', 'file',
  ]),

  meta('web_ui', 'Web UI', 'Web UI', 'Platform', false, [
    'web', 'ui', 'dashboard', 'listen',
  ]),
  meta('api', 'REST API', 'API', 'Platform', false, [
    'api', 'rest', 'token', 'websocket', 'request log',
  ]),
  meta('session', 'Session Storage', 'Session', 'Platform', false, [
    'session', 'redis', 'store', 'duration', 'cookie',
  ]),
  meta('mesh', 'Mesh Networking', 'Mesh', 'Platform', false, [
    'mesh', 'p2p', 'peer', 'stun', 'turn', 'coordinator', 'discovery', 'nat',
  ]),
  meta('auto_update', 'Auto Update', 'Auto Update', 'Platform', false, [
    'update', 'auto', 'channel', 'release', 'version',
  ]),
]

const BY_KEY: Record<ConfigSectionKey, ConfigSectionMeta> = CONFIG_SECTIONS.reduce(
  (acc, section) => {
    acc[section.key] = section
    return acc
  },
  {} as Record<ConfigSectionKey, ConfigSectionMeta>
)

export function getSectionMeta(key: ConfigSectionKey): ConfigSectionMeta {
  return BY_KEY[key]
}

/** Short label for a section key, falling back to the raw key for safety. */
export function sectionLabel(key: string): string {
  return BY_KEY[key as ConfigSectionKey]?.label ?? key
}

/** Sections grouped for the sidebar, preserving group and section order. */
export function groupedSections(
  sections: ConfigSectionMeta[] = CONFIG_SECTIONS
): Array<{ group: ConfigSectionGroup; sections: ConfigSectionMeta[] }> {
  return CONFIG_SECTION_GROUPS.map((group) => ({
    group,
    sections: sections.filter((s) => s.group === group),
  })).filter((entry) => entry.sections.length > 0)
}

/** Case-insensitive match of a section against a sidebar filter query. */
export function sectionMatchesQuery(section: ConfigSectionMeta, query: string): boolean {
  const q = query.trim().toLowerCase()
  if (!q) return true
  return (
    section.label.toLowerCase().includes(q) ||
    section.title.toLowerCase().includes(q) ||
    section.key.includes(q) ||
    section.group.toLowerCase().includes(q) ||
    section.keywords.some((k) => k.includes(q))
  )
}
