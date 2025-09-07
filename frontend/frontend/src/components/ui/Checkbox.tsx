import React, { forwardRef } from 'react'
import { Check } from 'lucide-react'
import { cn } from '@/utils/cn'
import type { CheckboxProps } from '@/types/ui'

export const Checkbox = forwardRef<HTMLInputElement, CheckboxProps>(
  ({
    label,
    description,
    checked,
    defaultChecked,
    onChange,
    disabled = false,
    required = false,
    error,
    className,
    name,
    id,
    'data-testid': testId,
    ...props
  }, ref) => {
    const checkboxId = id || name

    const handleChange = (event: React.ChangeEvent<HTMLInputElement>) => {
      onChange?.(event.target.checked)
    }

    return (
      <div className={cn('form-group', className)}>
        <div className="flex items-start">
          <div className="flex items-center h-5">
            <div className="relative">
              <input
                ref={ref}
                type="checkbox"
                id={checkboxId}
                name={name}
                checked={checked}
                defaultChecked={defaultChecked}
                onChange={handleChange}
                disabled={disabled}
                required={required}
                data-testid={testId}
                className="sr-only"
                {...props}
              />
              
              <div
                className={cn(
                  'w-4 h-4 rounded border-2 flex items-center justify-center transition-all duration-200',
                  checked
                    ? 'bg-primary-600 border-primary-600'
                    : 'bg-white border-secondary-300 hover:border-secondary-400',
                  disabled && 'opacity-50 cursor-not-allowed',
                  error && 'border-error-300',
                  !disabled && 'cursor-pointer'
                )}
              >
                {checked && (
                  <Check className="w-3 h-3 text-white" strokeWidth={3} />
                )}
              </div>
            </div>
          </div>
          
          {(label || description) && (
            <div className="ml-3">
              {label && (
                <label
                  htmlFor={checkboxId}
                  className={cn(
                    'text-sm font-medium text-secondary-900',
                    !disabled && 'cursor-pointer',
                    disabled && 'opacity-50'
                  )}
                >
                  {label}
                  {required && <span className="text-error-500 ml-1">*</span>}
                </label>
              )}
              {description && (
                <p className="text-sm text-secondary-500 mt-1">{description}</p>
              )}
            </div>
          )}
        </div>
        
        {error && <p className="form-error mt-2">{error}</p>}
      </div>
    )
  }
)

Checkbox.displayName = 'Checkbox'