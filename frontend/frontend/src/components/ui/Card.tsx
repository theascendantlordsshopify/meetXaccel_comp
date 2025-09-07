import React from 'react'
import { cn } from '@/utils/cn'
import type { CardProps, CardHeaderProps, CardContentProps, CardFooterProps } from '@/types/ui'

const cardVariants = {
  default: 'card',
  outlined: 'border border-secondary-200 bg-white',
  elevated: 'shadow-medium bg-white',
}

export function Card({
  variant = 'default',
  padding = true,
  className,
  children,
  onClick,
  hoverable = false,
  'data-testid': testId,
  ...props
}: CardProps) {
  const Component = onClick ? 'button' : 'div'
  
  return (
    <Component
      onClick={onClick}
      data-testid={testId}
      className={cn(
        cardVariants[variant],
        padding && 'p-6',
        onClick && 'cursor-pointer',
        hoverable && 'hover:shadow-medium transition-shadow duration-200',
        className
      )}
      {...props}
    >
      {children}
    </Component>
  )
}

export function CardHeader({
  title,
  subtitle,
  action,
  className,
  children,
}: CardHeaderProps) {
  return (
    <div className={cn('card-header', className)}>
      {(title || subtitle || action) && (
        <div className="flex items-start justify-between">
          <div className="min-w-0 flex-1">
            {title && (
              <h3 className="text-lg font-semibold text-secondary-900 leading-6">
                {title}
              </h3>
            )}
            {subtitle && (
              <p className="mt-1 text-sm text-secondary-500">
                {subtitle}
              </p>
            )}
          </div>
          {action && <div className="ml-4 flex-shrink-0">{action}</div>}
        </div>
      )}
      {children}
    </div>
  )
}

export function CardContent({ className, children }: CardContentProps) {
  return (
    <div className={cn('card-content', className)}>
      {children}
    </div>
  )
}

export function CardFooter({ className, children }: CardFooterProps) {
  return (
    <div className={cn('card-footer', className)}>
      {children}
    </div>
  )
}