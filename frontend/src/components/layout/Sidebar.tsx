import React from 'react'
import { NavLink } from 'react-router-dom'
import { ChevronRight, Calendar } from 'lucide-react'
import { cn } from '@/utils/cn'
import { useUI } from '@/stores/uiStore'
import { NAVIGATION } from '@/constants/routes'
import type { SidebarProps } from '@/types/ui'

export function Sidebar({ className }: Omit<SidebarProps, 'navigation' | 'collapsed' | 'onToggle'>) {
  const { sidebarCollapsed } = useUI()

  return (
    <div className={cn(
      'flex flex-col bg-white border-r border-secondary-200 transition-all duration-300',
      sidebarCollapsed ? 'w-16' : 'w-64',
      className
    )}>
      {/* Logo */}
      <div className="flex items-center h-16 px-4 border-b border-secondary-200">
        <div className="flex items-center space-x-2">
          <Calendar className="h-8 w-8 text-primary-600" />
          {!sidebarCollapsed && (
            <span className="text-xl font-bold text-secondary-900">
              Calendly Clone
            </span>
          )}
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-2 py-4 space-y-1 overflow-y-auto">
        {NAVIGATION.map((item) => (
          <div key={item.name}>
            <NavLink
              to={item.href}
              className={({ isActive }) => cn(
                'sidebar-nav-item group',
                isActive && 'active'
              )}
              title={sidebarCollapsed ? item.name : undefined}
            >
              {/* Icon */}
              <div className="flex-shrink-0">
                {/* You would import actual icons here based on item.icon */}
                <div className="h-5 w-5 bg-secondary-400 rounded" />
              </div>
              
              {!sidebarCollapsed && (
                <>
                  <span className="flex-1">{item.name}</span>
                  {item.children && (
                    <ChevronRight className="h-4 w-4 text-secondary-400 group-hover:text-secondary-600" />
                  )}
                </>
              )}
            </NavLink>

            {/* Sub-navigation */}
            {!sidebarCollapsed && item.children && (
              <div className="ml-6 mt-1 space-y-1">
                {item.children.map((child) => (
                  <NavLink
                    key={child.name}
                    to={child.href}
                    className={({ isActive }) => cn(
                      'block px-3 py-2 text-sm text-secondary-600 hover:text-secondary-900 hover:bg-secondary-50 rounded-md transition-colors',
                      isActive && 'text-primary-900 bg-primary-50'
                    )}
                  >
                    {child.name}
                  </NavLink>
                ))}
              </div>
            )}
          </div>
        ))}
      </nav>
    </div>
  )
}