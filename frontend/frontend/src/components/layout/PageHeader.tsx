import React from 'react'
import { cn } from '@/utils/cn'
import type { HeaderProps } from '@/types/ui'

export function PageHeader({
  title,
  subtitle,
  action,
  breadcrumbs,
  className,
}: HeaderProps) {
  return (
    <div className={cn('bg-white border-b border-secondary-200', className)}>
      <div className="px-4 sm:px-6 lg:px-8 py-6">
        {breadcrumbs && (
          <nav className="flex mb-4" aria-label="Breadcrumb">
            <ol className="flex items-center space-x-2 text-sm">
              {breadcrumbs.map((crumb, index) => (
                <li key={index} className="flex items-center">
                  {index > 0 && (
                    <span className="text-secondary-400 mx-2">/</span>
                  )}
                  {crumb.href ? (
                    <a
                      href={crumb.href}
                      className="text-secondary-500 hover:text-secondary-700 transition-colors"
                    >
                      {crumb.label}
                    </a>
                  ) : (
                    <span className={cn(
                      crumb.current ? 'text-secondary-900 font-medium' : 'text-secondary-500'
                    )}>
                      {crumb.label}
                    </span>
                  )}
                </li>
              ))}
            </ol>
          </nav>
        )}
        
        <div className="flex items-center justify-between">
          <div className="min-w-0 flex-1">
            {title && (
              <h1 className="text-3xl font-bold text-secondary-900 leading-tight">
                {title}
              </h1>
            )}
            
            {subtitle && (
              <p className="mt-2 text-lg text-secondary-600">
                {subtitle}
              </p>
            )}
          </div>
          
          {action && (
            <div className="ml-6 flex-shrink-0">
              {action}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}