import type { HealthCheckConfig, HealthCheckScheme } from '../../api/types'

/**
 * Shared health-check editing rules, used by both the global health check
 * section and the per-backend health check form.
 *
 * The server rejects settings that could never take effect — `scheme` or
 * `insecure_skip_verify` on a non-HTTP check, and `insecure_skip_verify`
 * without `scheme: https`. Normalising here (rather than in each form) means
 * changing the check type can never leave behind a field that makes the whole
 * config unsaveable, and the two editors cannot drift apart.
 */

/** Check type that supports scheme / insecure_skip_verify. */
export const HEALTH_CHECK_TYPE_HTTP = 'http'

export const HEALTH_CHECK_SCHEME_HTTP: HealthCheckScheme = 'http'
export const HEALTH_CHECK_SCHEME_HTTPS: HealthCheckScheme = 'https'

/** Defaults applied when a health check is first enabled. */
export const DEFAULT_HEALTH_CHECK: HealthCheckConfig = {
  type: 'tcp',
  interval: '10s',
  timeout: '5s',
}

/**
 * Applies a check-type change, dropping HTTP-only fields that would otherwise
 * be rejected by the server as inert.
 */
export function withHealthCheckType(
  config: HealthCheckConfig,
  type: HealthCheckConfig['type']
): HealthCheckConfig {
  const next: HealthCheckConfig = { ...config, type }
  if (type !== HEALTH_CHECK_TYPE_HTTP) {
    delete next.scheme
    delete next.insecure_skip_verify
  }
  return next
}

/**
 * Applies a scheme change. `http` is the server-side default, so it is omitted
 * rather than written out — otherwise merely opening the dropdown and
 * re-selecting the displayed value would mark the section modified and persist a
 * redundant key. Selecting anything other than HTTPS also clears
 * `insecure_skip_verify`, which the server only accepts with HTTPS.
 */
export function withHealthCheckScheme(
  config: HealthCheckConfig,
  scheme: HealthCheckScheme
): HealthCheckConfig {
  const next: HealthCheckConfig = { ...config, scheme }
  if (scheme === HEALTH_CHECK_SCHEME_HTTP) {
    delete next.scheme
  }
  if (scheme !== HEALTH_CHECK_SCHEME_HTTPS) {
    delete next.insecure_skip_verify
  }
  return next
}
