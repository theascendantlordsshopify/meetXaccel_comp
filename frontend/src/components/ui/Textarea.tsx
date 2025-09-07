import React, { forwardRef } from 'react'
import { cn } from '@/utils/cn'
import type { TextareaProps } from '@/types/ui'

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({
    label,
    placeholder,
    value,
    defaultValue,
    onChange,
    onBlur,
    disabled = false,
    required = false,
    error,
    helpText,
    rows = 4,
    maxLength,
    className,
    name,
    id,
    'data-testid': testId,
    ...props
  }, ref) => {
    const textareaId = id || name

    return (
      <div className="form-group">
        {label && (
          <label htmlFor={textareaId} className="form-label">
            {label}
            {required && <span className="text-error-500 ml-1">*</span>}
          </label>
        )}
        
        <textarea
          ref={ref}
          id={textareaId}
          name={name}
          value={value}
          defaultValue={defaultValue}
          onChange={onChange}
          onBlur={onBlur}
          disabled={disabled}
          required={required}
          placeholder={placeholder}
          rows={rows}
          maxLength={maxLength}
          data-testid={testId}
          className={cn(
            'input resize-none',
            error && 'border-error-300 focus-visible:ring-error-500',
            disabled && 'bg-secondary-50 cursor-not-allowed',
            className
          )}
          {...props}
        />
        
        {maxLength && (
          <div className="mt-1 text-right">
            <span className="text-xs text-secondary-500">
              {(value?.toString() || '').length}/{maxLength}
            </span>
          </div>
        )}
        
        {error && <p className="form-error">{error}</p>}
        {helpText && !error && <p className="form-help">{helpText}</p>}
      </div>
    )
  }
)

Textarea.displayName = 'Textarea'