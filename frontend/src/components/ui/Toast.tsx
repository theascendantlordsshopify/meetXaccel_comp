import React, { useEffect } from 'react'
import { X, CheckCircle, XCircle, AlertTriangle, Info } from 'lucide-react'
import { cn } from '@/utils/cn'
import { Button } from './Button'
import type { ToastProps } from '@/types/ui'

const toastIcons = {
  success: CheckCircle,
  error: XCircle,
  warning: AlertTriangle,
  info: Info,
}

const toastStyles = {
  success: 'bg-success-50 border-success-200 text-success-800',
  error: 'bg-error-50 border-error-200 text-error-800',
  warning: 'bg-warning-50 border-warning-200 text-warning-800',
  info: 'bg-primary-50 border-primary-200 text-primary-800',
}

const iconStyles = {
  success: 'text-success-400',
  error: 'text-error-400',
  warning: 'text-warning-400',
  info: 'text-primary-400',
}

export function Toast({
  id,
  type,
  title,
  message,
  duration = 5000,
  action,
  onDismiss,
}: ToastProps) {
  const Icon = toastIcons[type]

  useEffect(() => {
    if (duration > 0) {
      const timer = setTimeout(() => {
        onDismiss(id)
      }, duration)

      return () => clearTimeout(timer)
    }
  }, [id, duration, onDismiss])

  return (
    <div
      className={cn(
        'max-w-sm w-full shadow-strong rounded-lg border pointer-events-auto overflow-hidden',
        toastStyles[type]
      )}
    >
      <div className="p-4">
        <div className="flex items-start">
          <div className="flex-shrink-0">
            <Icon className={cn('h-5 w-5', iconStyles[type])} />
          </div>
          
          <div className="ml-3 w-0 flex-1">
            <p className="text-sm font-medium">{title}</p>
            {message && (
              <p className="mt-1 text-sm opacity-90">{message}</p>
            )}
            
            {action && (
              <div className="mt-3">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={action.onClick}
                  className="text-xs"
                >
                  {action.label}
                </Button>
              </div>
            )}
          </div>
          
          <div className="ml-4 flex-shrink-0 flex">
            <button
              type="button"
              onClick={() => onDismiss(id)}
              className="rounded-md inline-flex text-secondary-400 hover:text-secondary-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

export function ToastContainer({ 
  toasts, 
  onDismiss 
}: { 
  toasts: ToastProps[]
  onDismiss: (id: string) => void 
}) {
  return (
    <div className="fixed top-0 right-0 z-50 p-6 space-y-4 pointer-events-none">
      {toasts.map((toast) => (
        <div key={toast.id} className="animate-slide-down">
          <Toast {...toast} onDismiss={onDismiss} />
        </div>
      ))}
    </div>
  )
}