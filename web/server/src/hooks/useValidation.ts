import { useState, useCallback } from 'react'
import { validate, type Validator, type ValidationResult } from '../utils/validation'

/** Schema definition for field validation. */
export type ValidationSchema<T> = {
  [K in keyof T]?: Array<Validator<T[K]>>
}

/** Validation errors map. */
export type ValidationErrors<T> = Partial<Record<keyof T, string>>

/**
 * Hook for field-at-a-time form validation. The public surface intentionally
 * contains only what its callers use; broader speculative helpers made it
 * look as if forms blocked submit on aggregate errors when none did.
 */
export function useValidation<T extends Record<string, unknown>>(
  schema: ValidationSchema<T>
) {
  const [errors, setErrors] = useState<ValidationErrors<T>>({})

  const validateField = useCallback(
    (field: keyof T, value: T[keyof T]): ValidationResult => {
      const validators = schema[field]
      if (!validators) return null
      return validate(value, validators as Array<Validator<unknown>>)
    },
    [schema]
  )

  const clearErrors = useCallback(() => {
    setErrors({})
  }, [])

  const handleFieldChange = useCallback(
    (field: keyof T, value: T[keyof T]): ValidationResult => {
      const error = validateField(field, value)
      if (error) {
        setErrors((prev) => ({ ...prev, [field]: error }))
      } else {
        setErrors((prev) => {
          const next = { ...prev }
          delete next[field]
          return next
        })
      }
      return error
    },
    [validateField]
  )

  return { errors, clearErrors, handleFieldChange }
}

export default useValidation
