/**
 * Validation utility functions for split tunnel inputs
 */

/**
 * Validates a domain name format
 * Allows wildcards like *.example.com
 */
export function validateDomain(value: string): string | null {
  if (!value.trim()) return null
  const domainPattern = /^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/
  if (!domainPattern.test(value)) {
    return 'Invalid domain format. Use format like "example.com" or "*.example.com"'
  }
  return null
}

/**
 * Validates an IP address with optional CIDR notation
 * Supports IPv4 and IPv6
 */
export function validateIP(value: string): string | null {
  if (!value.trim()) return null

  // IPv4 pattern
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/
  // IPv6 pattern (simplified)
  const ipv6Pattern = /^([0-9a-fA-F:]+)(\/\d{1,3})?$/

  if (ipv4Pattern.test(value)) {
    // Validate IPv4 octets
    const parts = value.split('/')[0].split('.')
    for (const part of parts) {
      const num = parseInt(part, 10)
      if (num < 0 || num > 255) {
        return 'Invalid IPv4 address. Each octet must be 0-255'
      }
    }
    // Validate CIDR if present
    if (value.includes('/')) {
      const cidr = parseInt(value.split('/')[1], 10)
      if (cidr < 0 || cidr > 32) {
        return 'Invalid CIDR notation. IPv4 prefix must be 0-32'
      }
    }
    return null
  }

  if (ipv6Pattern.test(value)) {
    // Validate IPv6 CIDR if present
    if (value.includes('/')) {
      const cidr = parseInt(value.split('/')[1], 10)
      if (cidr < 0 || cidr > 128) {
        return 'Invalid CIDR notation. IPv6 prefix must be 0-128'
      }
    }
    return null
  }

  return 'Invalid IP format. Use IPv4 (e.g., "10.0.0.0/8") or IPv6'
}

/**
 * Validates CIDR notation (IPv4 only)
 */
export function validateCIDR(value: string): string | null {
  if (!value.trim()) return null
  // Match IPv4 CIDR notation (e.g., 192.168.1.0/24) or plain IP
  const cidrPattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/
  if (!cidrPattern.test(value)) {
    return 'Invalid IP/CIDR format. Use format like "192.168.1.0/24" or "10.0.0.1"'
  }
  // Validate IP octets are in range
  const ipPart = value.split('/')[0]
  const octets = ipPart.split('.').map(Number)
  if (octets.some(o => o < 0 || o > 255)) {
    return 'Invalid IP address. Each octet must be 0-255'
  }
  // Validate CIDR prefix if present
  if (value.includes('/')) {
    const prefix = parseInt(value.split('/')[1])
    if (prefix < 0 || prefix > 32) {
      return 'Invalid CIDR prefix. Must be 0-32'
    }
  }
  return null
}

/**
 * Validates either a domain or IP/CIDR
 */
export function validateDomainOrIP(value: string): string | null {
  // Try domain first, then IP
  const domainError = validateDomain(value)
  const ipError = validateIP(value)

  if (domainError === null || ipError === null) {
    return null // Valid if either is valid
  }

  return 'Invalid format. Enter a domain (e.g., "example.com") or IP/CIDR (e.g., "10.0.0.0/8")'
}
