import React from 'react'
import { User } from 'lucide-react'
import { cn } from '@/utils/cn'
import { getInitials, stringToColor } from '@/utils/helpers'

interface AvatarProps {
  src?: string
  name?: string
  size?: 'sm' | 'md' | 'lg' | 'xl'
  className?: string
}

const avatarSizes = {
  sm: 'h-6 w-6 text-xs',
  md: 'h-8 w-8 text-sm',
  lg: 'h-10 w-10 text-base',
  xl: 'h-12 w-12 text-lg',
}

export function Avatar({ 
  src, 
  name, 
  size = 'md', 
  className 
}: AvatarProps) {
  const initials = name ? getInitials(name) : ''
  const backgroundColor = name ? stringToColor(name) : '#6b7280'

  if (src) {
    return (
      <img
        src={src}
        alt={name || 'Avatar'}
        className={cn(
          'rounded-full object-cover',
          avatarSizes[size],
          className
        )}
      />
    )
  }

  return (
    <div
      className={cn(
        'rounded-full flex items-center justify-center font-medium text-white',
        avatarSizes[size],
        className
      )}
      style={{ backgroundColor }}
    >
      {initials || <User className="h-1/2 w-1/2" />}
    </div>
  )
}