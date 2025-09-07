import React from 'react'
import { Outlet } from 'react-router-dom'
import { Header } from './Header'
import { Sidebar } from './Sidebar'
import { ToastContainer } from '@/components/ui/Toast'
import { useUI } from '@/stores/uiStore'
import { cn } from '@/utils/cn'

export function Layout() {
  const { sidebarCollapsed, notifications, removeNotification } = useUI()

  return (
    <div className="h-screen flex overflow-hidden bg-secondary-50">
      {/* Sidebar */}
      <Sidebar />

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header />
        
        <main className="flex-1 overflow-y-auto">
          <div className={cn(
            'transition-all duration-300',
            sidebarCollapsed ? 'ml-16' : 'ml-64'
          )}>
            <Outlet />
          </div>
        </main>
      </div>

      {/* Toast notifications */}
      <ToastContainer 
        toasts={notifications} 
        onDismiss={removeNotification} 
      />
    </div>
  )
}