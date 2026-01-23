import { InputHTMLAttributes, forwardRef } from 'react'

export interface ValidatedInputProps extends InputHTMLAttributes<HTMLInputElement> {
  /** Error message to display */
  error?: string | null
  /** Label text */
  label?: string
  /** Help text shown below the input */
  helpText?: string
  /** Whether to show the error inline (below input) or only as border color */
  showErrorMessage?: boolean
  /** Custom wrapper className */
  wrapperClassName?: string
}

/**
 * Input component with validation styling
 *
 * Shows red border and error message when error prop is provided.
 */
export const ValidatedInput = forwardRef<HTMLInputElement, ValidatedInputProps>(
  (
    {
      error,
      label,
      helpText,
      showErrorMessage = true,
      wrapperClassName = '',
      className = '',
      id,
      ...props
    },
    ref
  ) => {
    const inputId = id || (label ? label.toLowerCase().replace(/\s+/g, '-') : undefined)
    const hasError = !!error

    const inputClasses = [
      'input',
      hasError && 'input-error',
      className,
    ]
      .filter(Boolean)
      .join(' ')

    return (
      <div className={wrapperClassName}>
        {label && (
          <label
            htmlFor={inputId}
            className="block text-sm font-medium text-gray-300 mb-1"
          >
            {label}
          </label>
        )}
        <input
          ref={ref}
          id={inputId}
          className={inputClasses}
          aria-invalid={hasError}
          aria-describedby={
            hasError && showErrorMessage
              ? `${inputId}-error`
              : helpText
                ? `${inputId}-help`
                : undefined
          }
          {...props}
        />
        {hasError && showErrorMessage && (
          <p
            id={`${inputId}-error`}
            className="text-xs text-bifrost-error mt-1"
            role="alert"
          >
            {error}
          </p>
        )}
        {!hasError && helpText && (
          <p id={`${inputId}-help`} className="text-xs text-bifrost-muted mt-1">
            {helpText}
          </p>
        )}
      </div>
    )
  }
)

ValidatedInput.displayName = 'ValidatedInput'

export interface ValidatedSelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  /** Error message to display */
  error?: string | null
  /** Label text */
  label?: string
  /** Help text shown below the select */
  helpText?: string
  /** Whether to show the error inline (below select) or only as border color */
  showErrorMessage?: boolean
  /** Custom wrapper className */
  wrapperClassName?: string
  /** Children (options) */
  children: React.ReactNode
}

/**
 * Select component with validation styling
 */
export const ValidatedSelect = forwardRef<HTMLSelectElement, ValidatedSelectProps>(
  (
    {
      error,
      label,
      helpText,
      showErrorMessage = true,
      wrapperClassName = '',
      className = '',
      id,
      children,
      ...props
    },
    ref
  ) => {
    const selectId = id || (label ? label.toLowerCase().replace(/\s+/g, '-') : undefined)
    const hasError = !!error

    const selectClasses = [
      'input',
      hasError && 'input-error',
      className,
    ]
      .filter(Boolean)
      .join(' ')

    return (
      <div className={wrapperClassName}>
        {label && (
          <label
            htmlFor={selectId}
            className="block text-sm font-medium text-gray-300 mb-1"
          >
            {label}
          </label>
        )}
        <select
          ref={ref}
          id={selectId}
          className={selectClasses}
          aria-invalid={hasError}
          aria-describedby={
            hasError && showErrorMessage
              ? `${selectId}-error`
              : helpText
                ? `${selectId}-help`
                : undefined
          }
          {...props}
        >
          {children}
        </select>
        {hasError && showErrorMessage && (
          <p
            id={`${selectId}-error`}
            className="text-xs text-bifrost-error mt-1"
            role="alert"
          >
            {error}
          </p>
        )}
        {!hasError && helpText && (
          <p id={`${selectId}-help`} className="text-xs text-bifrost-muted mt-1">
            {helpText}
          </p>
        )}
      </div>
    )
  }
)

ValidatedSelect.displayName = 'ValidatedSelect'

export interface ValidatedTextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  /** Error message to display */
  error?: string | null
  /** Label text */
  label?: string
  /** Help text shown below the textarea */
  helpText?: string
  /** Whether to show the error inline (below textarea) or only as border color */
  showErrorMessage?: boolean
  /** Custom wrapper className */
  wrapperClassName?: string
}

/**
 * Textarea component with validation styling
 */
export const ValidatedTextarea = forwardRef<HTMLTextAreaElement, ValidatedTextareaProps>(
  (
    {
      error,
      label,
      helpText,
      showErrorMessage = true,
      wrapperClassName = '',
      className = '',
      id,
      ...props
    },
    ref
  ) => {
    const textareaId = id || (label ? label.toLowerCase().replace(/\s+/g, '-') : undefined)
    const hasError = !!error

    const textareaClasses = [
      'input',
      hasError && 'input-error',
      className,
    ]
      .filter(Boolean)
      .join(' ')

    return (
      <div className={wrapperClassName}>
        {label && (
          <label
            htmlFor={textareaId}
            className="block text-sm font-medium text-gray-300 mb-1"
          >
            {label}
          </label>
        )}
        <textarea
          ref={ref}
          id={textareaId}
          className={textareaClasses}
          aria-invalid={hasError}
          aria-describedby={
            hasError && showErrorMessage
              ? `${textareaId}-error`
              : helpText
                ? `${textareaId}-help`
                : undefined
          }
          {...props}
        />
        {hasError && showErrorMessage && (
          <p
            id={`${textareaId}-error`}
            className="text-xs text-bifrost-error mt-1"
            role="alert"
          >
            {error}
          </p>
        )}
        {!hasError && helpText && (
          <p id={`${textareaId}-help`} className="text-xs text-bifrost-muted mt-1">
            {helpText}
          </p>
        )}
      </div>
    )
  }
)

ValidatedTextarea.displayName = 'ValidatedTextarea'
