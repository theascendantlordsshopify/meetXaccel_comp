import React, { forwardRef } from 'react'
import { cn } from '@/utils/cn'
import type { InputProps } from '@/types/ui'

const inputSizes = {
  sm: 'h-8 px-2 text-xs',
  md: 'h-10 px-3 text-sm',
  lg: 'h-12 px-4 text-base',
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({
    type = 'text',
    size = 'md',
    label,
    placeholder,
    value,
    defaultValue,
    onChange,
    onBlur,
    onFocus,
    disabled = false,
    required = false,
    error,
    helpText,
    leftIcon,
    rightIcon,
    className,
    name,
    id,
    autoComplete,
    autoFocus,
    'data-testid': testId,
    ...props
  }, ref) => {
    const inputId = id || name

    return (
      <div className="form-group">
        {label && (
          <label htmlFor={inputId} className="form-label">
            {label}
            {required && <span className="text-error-500 ml-1">*</span>}
          </label>
        )}
        
        <div className="relative">
          {leftIcon && (
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <span className="text-secondary-400">{leftIcon}</span>
            </div>
          )}
          
          <input
            ref={ref}
            type={type}
            id={inputId}
            name={name}
            value={value}
            defaultValue={defaultValue}
            onChange={onChange}
            onBlur={onBlur}
            onFocus={onFocus}
            disabled={disabled}
            required={required}
            placeholder={placeholder}
            autoComplete={autoComplete}
            autoFocus={autoFocus}
            data-testid={testId}
            className={cn(
              'input',
              inputSizes[size],
              leftIcon && 'pl-10',
              rightIcon && 'pr-10',
              error && 'border-error-300 focus-visible:ring-error-500',
              disabled && 'bg-secondary-50 cursor-not-allowed',
              className
            )}
            {...props}
          />
          
          {rightIcon && (
            <div className="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
              <span className="text-secondary-400">{rightIcon}</span>
            </div>
          )}
        </div>
        
        {error && <p className="form-error">{error}</p>}
        {helpText && !error && <p className="form-help">{helpText}</p>}
      </div>
    )
  }
)

Input.displayName = 'Input'