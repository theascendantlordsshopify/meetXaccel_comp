import React from 'react'
import { cn } from '@/utils/cn'
import type { BadgeProps } from '@/types/ui'

const badgeVariants = {
  primary: 'badge-primary',
  secondary: 'badge-secondary',
  success: 'badge-success',
  warning: 'badge-warning',
  error: 'badge-error',
  info: 'bg-primary-100 text-primary-800',
}

const badgeSizes = {
  sm: 'px-2 py-0.5 text-xs',
  md: 'px-2.5 py-0.5 text-xs',
  lg: 'px-3 py-1 text-sm',
}

export function Badge({
  variant = 'secondary',
  size = 'md',
  children,
  className,
  'data-testid': testId,
}: BadgeProps) {
  return (
    <span
      data-testid={testId}
      className={cn(
        'badge',
        badgeVariants[variant],
        badgeSizes[size],
        className
      )}
    >
      {children}
    </span>
  )
}