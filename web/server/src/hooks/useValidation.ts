import { useState, useCallback, useMemo } from 'react'
import { validate, hasErrors, type Validator, type ValidationResult } from '../utils/validation'

/**
 * Schema definition for field validation
 */
export type ValidationSchema<T> = {
  [K in keyof T]?: Array<Validator<T[K]>>
}

/**
 * Validation errors map
 */
export type ValidationErrors<T> = Partial<Record<keyof T, string>>

/**
 * Hook return type
 */
export interface UseValidationReturn<T> {
  /** Current validation errors */
  errors: ValidationErrors<T>
  /** Whether any errors exist */
  hasErrors: boolean
  /** Validate a single field */
  validateField: (field: keyof T, value: T[keyof T]) => ValidationResult
  /** Validate all fields at once */
  validateAll: (values: T) => ValidationErrors<T>
  /** Clear error for a specific field */
  clearError: (field: keyof T) => void
  /** Clear all errors */
  clearErrors: () => void
  /** Set error for a specific field */
  setError: (field: keyof T, error: string) => void
  /** Set multiple errors at once */
  setErrors: (errors: ValidationErrors<T>) => void
  /** Get input props with error handling */
  getFieldProps: (field: keyof T) => { error: string | undefined; 'aria-invalid': boolean }
  /** Validate field and update errors (for onChange handlers) */
  handleFieldChange: (field: keyof T, value: T[keyof T]) => ValidationResult
}

/**
 * Hook for managing form validation state
 *
 * @param schema - Validation schema mapping field names to arrays of validators
 * @returns Validation state and helper functions
 *
 * @example
 * ```tsx
 * const { errors, validateField, handleFieldChange, hasErrors } = useValidation<ServerSettings>({
 *   'http.listen': [validators.required(), validators.listenAddress()],
 *   'http.read_timeout': [validators.duration()],
 * })
 *
 * // In onChange handler:
 * const handleChange = (field, value) => {
 *   handleFieldChange(field, value)
 *   onChange({ ...config, [field]: value })
 * }
 *
 * // In JSX:
 * <ValidatedInput
 *   value={config.http?.listen}
 *   error={errors['http.listen']}
 *   onChange={(e) => handleChange('http.listen', e.target.value)}
 * />
 * ```
 */
export function useValidation<T extends Record<string, unknown>>(
  schema: ValidationSchema<T>
): UseValidationReturn<T> {
  const [errors, setErrorsState] = useState<ValidationErrors<T>>({})

  const validateField = useCallback(
    (field: keyof T, value: T[keyof T]): ValidationResult => {
      const validators = schema[field]
      if (!validators) return null
      return validate(value, validators as Array<Validator<unknown>>)
    },
    [schema]
  )

  const validateAllFields = useCallback(
    (values: T): ValidationErrors<T> => {
      const newErrors: ValidationErrors<T> = {}
      for (const field of Object.keys(schema) as Array<keyof T>) {
        const error = validateField(field, values[field])
        if (error) {
          newErrors[field] = error
        }
      }
      return newErrors
    },
    [schema, validateField]
  )

  const clearError = useCallback((field: keyof T) => {
    setErrorsState((prev) => {
      const next = { ...prev }
      delete next[field]
      return next
    })
  }, [])

  const clearErrors = useCallback(() => {
    setErrorsState({})
  }, [])

  const setError = useCallback((field: keyof T, error: string) => {
    setErrorsState((prev) => ({ ...prev, [field]: error }))
  }, [])

  const setMultipleErrors = useCallback((newErrors: ValidationErrors<T>) => {
    setErrorsState(newErrors)
  }, [])

  const handleFieldChange = useCallback(
    (field: keyof T, value: T[keyof T]): ValidationResult => {
      const error = validateField(field, value)
      if (error) {
        setErrorsState((prev) => ({ ...prev, [field]: error }))
      } else {
        setErrorsState((prev) => {
          const next = { ...prev }
          delete next[field]
          return next
        })
      }
      return error
    },
    [validateField]
  )

  const getFieldProps = useCallback(
    (field: keyof T) => ({
      error: errors[field],
      'aria-invalid': !!errors[field],
    }),
    [errors]
  )

  const hasValidationErrors = useMemo(() => hasErrors(errors as Record<string, string>), [errors])

  return {
    errors,
    hasErrors: hasValidationErrors,
    validateField,
    validateAll: validateAllFields,
    clearError,
    clearErrors,
    setError,
    setErrors: setMultipleErrors,
    getFieldProps,
    handleFieldChange,
  }
}

export default useValidation
