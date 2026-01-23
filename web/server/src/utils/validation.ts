/**
 * Validation utilities for form fields
 *
 * Provides a consistent validation pattern across all config sections.
 */

export type ValidationResult = string | null

export type Validator<T = unknown> = (value: T) => ValidationResult

/**
 * Common validators for form fields
 */
export const validators = {
  /**
   * Validates that a value is not empty
   */
  required: (message = 'This field is required'): Validator<unknown> => {
    return (value: unknown): ValidationResult => {
      if (value === undefined || value === null || value === '') {
        return message
      }
      if (typeof value === 'string' && value.trim() === '') {
        return message
      }
      return null
    }
  },

  /**
   * Validates minimum string length
   */
  minLength: (min: number, message?: string): Validator<string> => {
    return (value: string): ValidationResult => {
      if (value && value.length < min) {
        return message || `Must be at least ${min} characters`
      }
      return null
    }
  },

  /**
   * Validates maximum string length
   */
  maxLength: (max: number, message?: string): Validator<string> => {
    return (value: string): ValidationResult => {
      if (value && value.length > max) {
        return message || `Must be at most ${max} characters`
      }
      return null
    }
  },

  /**
   * Validates string against a regex pattern
   */
  pattern: (regex: RegExp, message = 'Invalid format'): Validator<string> => {
    return (value: string): ValidationResult => {
      if (value && !regex.test(value)) {
        return message
      }
      return null
    }
  },

  /**
   * Validates numeric range
   */
  range: (min: number, max: number, message?: string): Validator<number> => {
    return (value: number): ValidationResult => {
      if (value !== undefined && value !== null && (value < min || value > max)) {
        return message || `Must be between ${min} and ${max}`
      }
      return null
    }
  },

  /**
   * Validates minimum number
   */
  min: (min: number, message?: string): Validator<number> => {
    return (value: number): ValidationResult => {
      if (value !== undefined && value !== null && value < min) {
        return message || `Must be at least ${min}`
      }
      return null
    }
  },

  /**
   * Validates maximum number
   */
  max: (max: number, message?: string): Validator<number> => {
    return (value: number): ValidationResult => {
      if (value !== undefined && value !== null && value > max) {
        return message || `Must be at most ${max}`
      }
      return null
    }
  },

  /**
   * Validates a valid port number (1-65535)
   */
  port: (message = 'Port must be between 1 and 65535'): Validator<number> => {
    return (value: number): ValidationResult => {
      if (value !== undefined && value !== null && (value < 1 || value > 65535)) {
        return message
      }
      return null
    }
  },

  /**
   * Validates a listen address format (e.g., ":8080", "0.0.0.0:8080", "localhost:8080")
   */
  listenAddress: (message = 'Invalid listen address format (e.g., :8080 or 0.0.0.0:8080)'): Validator<string> => {
    return (value: string): ValidationResult => {
      if (!value) return null
      // Match formats: ":port", "host:port", "[ipv6]:port"
      const listenPattern = /^((\[[\da-fA-F:]+\]|[\w.-]*):)?(\d{1,5})$/
      if (!listenPattern.test(value)) {
        return message
      }
      // Also validate the port portion
      const portMatch = value.match(/:(\d+)$/)
      if (portMatch) {
        const port = parseInt(portMatch[1], 10)
        if (port < 1 || port > 65535) {
          return 'Port must be between 1 and 65535'
        }
      }
      return null
    }
  },

  /**
   * Validates URL format
   */
  url: (message = 'Invalid URL format'): Validator<string> => {
    return (value: string): ValidationResult => {
      if (!value) return null
      try {
        new URL(value)
        return null
      } catch {
        return message
      }
    }
  },

  /**
   * Validates URL with specific allowed protocols
   */
  urlWithProtocol: (protocols: string[], message?: string): Validator<string> => {
    return (value: string): ValidationResult => {
      if (!value) return null
      try {
        const url = new URL(value)
        const protocol = url.protocol.replace(':', '')
        if (!protocols.includes(protocol)) {
          return message || `URL must use ${protocols.join(' or ')} protocol`
        }
        return null
      } catch {
        return message || 'Invalid URL format'
      }
    }
  },

  /**
   * Validates IPv4 address
   */
  ipv4: (message = 'Invalid IPv4 address'): Validator<string> => {
    return (value: string): ValidationResult => {
      if (!value) return null
      const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/
      if (!ipv4Pattern.test(value)) {
        return message
      }
      const parts = value.split('.').map(Number)
      if (parts.some((p) => p > 255)) {
        return message
      }
      return null
    }
  },

  /**
   * Validates IPv4 or IPv6 address
   */
  ip: (message = 'Invalid IP address'): Validator<string> => {
    return (value: string): ValidationResult => {
      if (!value) return null
      // Simple IPv4 check
      const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/
      if (ipv4Pattern.test(value)) {
        const parts = value.split('.').map(Number)
        if (!parts.some((p) => p > 255)) {
          return null
        }
      }
      // Simple IPv6 check (very basic)
      const ipv6Pattern = /^[\da-fA-F:]+$/
      if (ipv6Pattern.test(value) && value.includes(':')) {
        return null
      }
      return message
    }
  },

  /**
   * Validates Go duration format (e.g., "30s", "5m", "1h30m")
   */
  duration: (message = 'Invalid duration format (e.g., 30s, 5m, 1h)'): Validator<string> => {
    return (value: string): ValidationResult => {
      if (!value) return null
      // Go duration pattern: optional negative, number followed by unit(s)
      const durationPattern = /^-?(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$/
      if (!durationPattern.test(value)) {
        return message
      }
      return null
    }
  },

  /**
   * Validates byte size format (e.g., "10MB", "1GB", "500KB")
   */
  byteSize: (message = 'Invalid size format (e.g., 10MB, 1GB)'): Validator<string> => {
    return (value: string): ValidationResult => {
      if (!value) return null
      const sizePattern = /^\d+(\.\d+)?\s*(B|KB|MB|GB|TB|KiB|MiB|GiB|TiB|Kbps|Mbps|Gbps)?$/i
      if (!sizePattern.test(value)) {
        return message
      }
      return null
    }
  },

  /**
   * Validates file path format
   */
  filePath: (message = 'Invalid file path'): Validator<string> => {
    return (value: string): ValidationResult => {
      if (!value) return null
      // Basic path validation - must start with / or be a relative path
      // Allow alphanumeric, slashes, dots, hyphens, underscores
      const pathPattern = /^[/.]?[\w/.\\-]+$/
      if (!pathPattern.test(value)) {
        return message
      }
      return null
    }
  },

  /**
   * Validates domain name or wildcard pattern
   */
  domainPattern: (message = 'Invalid domain pattern'): Validator<string> => {
    return (value: string): ValidationResult => {
      if (!value) return null
      // Allow wildcards (*), alphanumeric, dots, hyphens
      const domainPattern = /^[*]?[\w*.-]+$/
      if (!domainPattern.test(value)) {
        return message
      }
      return null
    }
  },

  /**
   * Validates that a value is a positive integer
   */
  positiveInteger: (message = 'Must be a positive integer'): Validator<number> => {
    return (value: number): ValidationResult => {
      if (value !== undefined && value !== null) {
        if (!Number.isInteger(value) || value < 0) {
          return message
        }
      }
      return null
    }
  },

  /**
   * Validates email format
   */
  email: (message = 'Invalid email address'): Validator<string> => {
    return (value: string): ValidationResult => {
      if (!value) return null
      const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
      if (!emailPattern.test(value)) {
        return message
      }
      return null
    }
  },

  /**
   * Custom validator that only runs when value is not empty
   */
  whenNotEmpty: <T>(validator: Validator<T>): Validator<T> => {
    return (value: T): ValidationResult => {
      if (value === undefined || value === null || value === '') {
        return null
      }
      return validator(value)
    }
  },
}

/**
 * Combines multiple validators into one
 * Returns the first error encountered, or null if all pass
 */
export function validate<T>(value: T, rules: Array<Validator<T>>): ValidationResult {
  for (const rule of rules) {
    const error = rule(value)
    if (error) return error
  }
  return null
}

/**
 * Validates all fields in an object
 * Returns a map of field names to error messages
 */
export function validateAll<T extends Record<string, unknown>>(
  values: T,
  schema: { [K in keyof T]?: Array<Validator<T[K]>> }
): Partial<Record<keyof T, string>> {
  const errors: Partial<Record<keyof T, string>> = {}

  for (const field of Object.keys(schema) as Array<keyof T>) {
    const validators = schema[field]
    if (validators) {
      const error = validate(values[field], validators as Array<Validator<unknown>>)
      if (error) {
        errors[field] = error
      }
    }
  }

  return errors
}

/**
 * Checks if a validation result object has any errors
 */
export function hasErrors(errors: Record<string, string | null | undefined>): boolean {
  return Object.values(errors).some((e) => e !== null && e !== undefined)
}
