import React from 'react'
import { Badge } from '@/components/ui/Badge'
import { getStatusColor } from '@/utils/format'
import type { BadgeVariant } from '@/types/ui'

interface StatusBadgeProps {
  status: string
  className?: string
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const variant = getStatusColor(status) as BadgeVariant
  
  return (
    <Badge variant={variant} className={className}>
      {status.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
    </Badge>
  )
}