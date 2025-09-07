import React from 'react'
import { cn } from '@/utils/cn'
import { Button } from './Button'
import type { EmptyStateProps } from '@/types/ui'

export function EmptyState({
  icon,
  title,
  description,
  action,
  className,
}: EmptyStateProps) {
  return (
    <div className={cn('text-center py-12', className)}>
      {icon && (
        <div className="mx-auto h-12 w-12 text-secondary-400 mb-4">
          {icon}
        </div>
      )}
      
      <h3 className="text-lg font-medium text-secondary-900 mb-2">
        {title}
      </h3>
      
      {description && (
        <p className="text-secondary-500 mb-6 max-w-sm mx-auto">
          {description}
        </p>
      )}
      
      {action && (
        <Button onClick={action.onClick}>
          {action.label}
        </Button>
      )}
    </div>
  )
}