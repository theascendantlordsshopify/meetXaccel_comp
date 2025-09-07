import React from 'react'
import { cn } from '@/utils/cn'
import type { ButtonProps } from '@/types/ui'

const buttonVariants = {
  primary: 'btn-primary',
  secondary: 'btn-secondary', 
  outline: 'btn-outline',
  ghost: 'btn-ghost',
  danger: 'bg-error-600 text-white hover:bg-error-700 active:bg-error-800 shadow-sm hover:shadow-md',
}

const buttonSizes = {
  sm: 'btn-sm',
  md: 'btn-md', 
  lg: 'btn-lg',
}

export function Button({
  variant = 'primary',
  size = 'md',
  disabled = false,
  loading = false,
  fullWidth = false,
  leftIcon,
  rightIcon,
  children,
  onClick,
  type = 'button',
  className,
  'data-testid': testId,
  ...props
}: ButtonProps) {
  return (
    <button
      type={type}
      disabled={disabled || loading}
      onClick={onClick}
      data-testid={testId}
      className={cn(
        'btn',
        buttonVariants[variant],
        buttonSizes[size],
        fullWidth && 'w-full',
        (disabled || loading) && 'opacity-50 cursor-not-allowed',
        className
      )}
      {...props}
    >
      {loading && (
        <svg
          className="animate-spin -ml-1 mr-2 h-4 w-4"
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
        >
          <circle
            className="opacity-25"
            cx="12"
            cy="12"
            r="10"
            stroke="currentColor"
            strokeWidth="4"
          />
          <path
            className="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
          />
        </svg>
      )}
      {!loading && leftIcon && <span className="mr-2">{leftIcon}</span>}
      {children}
      {!loading && rightIcon && <span className="ml-2">{rightIcon}</span>}
    </button>
  )
}