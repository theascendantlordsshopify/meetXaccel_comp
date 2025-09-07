import React from 'react'
import { Bell, Search, Settings, User, LogOut, Menu } from 'lucide-react'
import { cn } from '@/utils/cn'
import { Button } from '@/components/ui/Button'
import { useAuth } from '@/hooks/useAuth'
import { useUI } from '@/stores/uiStore'
import type { HeaderProps } from '@/types/ui'

export function Header({
  title,
  subtitle,
  action,
  breadcrumbs,
  className,
}: HeaderProps) {
  const { user, logout, displayName } = useAuth()
  const { toggleSidebar, setCommandPaletteOpen } = useUI()

  return (
    <header className={cn('bg-white border-b border-secondary-200', className)}>
      <div className="px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Left side */}
          <div className="flex items-center space-x-4">
            <Button
              variant="ghost"
              size="sm"
              onClick={toggleSidebar}
              className="lg:hidden"
            >
              <Menu className="h-5 w-5" />
            </Button>
            
            <div className="min-w-0 flex-1">
              {breadcrumbs && (
                <nav className="flex mb-1" aria-label="Breadcrumb">
                  <ol className="flex items-center space-x-2 text-sm">
                    {breadcrumbs.map((crumb, index) => (
                      <li key={index} className="flex items-center">
                        {index > 0 && (
                          <span className="text-secondary-400 mx-2">/</span>
                        )}
                        {crumb.href ? (
                          <a
                            href={crumb.href}
                            className="text-secondary-500 hover:text-secondary-700"
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
              
              {title && (
                <h1 className="text-2xl font-bold text-secondary-900 leading-7">
                  {title}
                </h1>
              )}
              
              {subtitle && (
                <p className="mt-1 text-sm text-secondary-500">
                  {subtitle}
                </p>
              )}
            </div>
          </div>

          {/* Right side */}
          <div className="flex items-center space-x-4">
            {action && <div>{action}</div>}
            
            {/* Search */}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setCommandPaletteOpen(true)}
              className="hidden sm:flex"
            >
              <Search className="h-5 w-5" />
            </Button>

            {/* Notifications */}
            <Button variant="ghost" size="sm">
              <Bell className="h-5 w-5" />
            </Button>

            {/* User menu */}
            <div className="relative">
              <div className="flex items-center space-x-3">
                <div className="hidden sm:block text-right">
                  <p className="text-sm font-medium text-secondary-900">
                    {displayName}
                  </p>
                  <p className="text-xs text-secondary-500">
                    {user?.email}
                  </p>
                </div>
                
                <div className="flex items-center space-x-2">
                  <Button variant="ghost" size="sm">
                    <User className="h-5 w-5" />
                  </Button>
                  
                  <Button variant="ghost" size="sm">
                    <Settings className="h-5 w-5" />
                  </Button>
                  
                  <Button 
                    variant="ghost" 
                    size="sm"
                    onClick={() => logout()}
                  >
                    <LogOut className="h-5 w-5" />
                  </Button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </header>
  )
}