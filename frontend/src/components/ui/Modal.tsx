import React, { useEffect } from 'react'
import { createPortal } from 'react-dom'
import { X } from 'lucide-react'
import { cn } from '@/utils/cn'
import { useKeyboard } from '@/hooks/useKeyboard'
import { useClickOutside } from '@/hooks/useClickOutside'
import type { ModalProps } from '@/types/ui'

const modalSizes = {
  sm: 'max-w-md',
  md: 'max-w-lg',
  lg: 'max-w-2xl',
  xl: 'max-w-4xl',
  full: 'max-w-full mx-4',
}

export function Modal({
  isOpen,
  onClose,
  title,
  description,
  size = 'md',
  closeOnOverlayClick = true,
  closeOnEscape = true,
  showCloseButton = true,
  className,
  children,
}: ModalProps) {
  const modalRef = useClickOutside<HTMLDivElement>(() => {
    if (closeOnOverlayClick) {
      onClose()
    }
  })

  // Handle escape key
  useKeyboard('Escape', onClose, {
    preventDefault: closeOnEscape,
  })

  // Prevent body scroll when modal is open
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden'
      return () => {
        document.body.style.overflow = 'unset'
      }
    }
  }, [isOpen])

  if (!isOpen) return null

  return createPortal(
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex min-h-full items-center justify-center p-4">
        {/* Backdrop */}
        <div 
          className="fixed inset-0 bg-black bg-opacity-25 transition-opacity"
          aria-hidden="true"
        />
        
        {/* Modal */}
        <div
          ref={modalRef}
          className={cn(
            'relative w-full transform overflow-hidden rounded-xl bg-white shadow-strong transition-all',
            modalSizes[size],
            className
          )}
        >
          {/* Header */}
          {(title || description || showCloseButton) && (
            <div className="flex items-start justify-between p-6 pb-4">
              <div className="min-w-0 flex-1">
                {title && (
                  <h3 className="text-lg font-semibold text-secondary-900 leading-6">
                    {title}
                  </h3>
                )}
                {description && (
                  <p className="mt-1 text-sm text-secondary-500">
                    {description}
                  </p>
                )}
              </div>
              
              {showCloseButton && (
                <button
                  type="button"
                  onClick={onClose}
                  className="ml-4 rounded-lg p-1 text-secondary-400 hover:text-secondary-500 hover:bg-secondary-100 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 transition-colors"
                >
                  <X className="h-5 w-5" />
                </button>
              )}
            </div>
          )}
          
          {/* Content */}
          <div className={cn('px-6', !(title || description || showCloseButton) && 'pt-6')}>
            {children}
          </div>
          
          {/* Bottom padding */}
          <div className="pb-6" />
        </div>
      </div>
    </div>,
    document.body
  )
}