import React from 'react'
import { AlertTriangle, Info, AlertCircle } from 'lucide-react'
import { Modal } from '@/components/ui/Modal'
import { Button } from '@/components/ui/Button'
import type { ConfirmDialogProps } from '@/types/common'

const variantIcons = {
  danger: AlertTriangle,
  warning: AlertCircle,
  info: Info,
}

const variantStyles = {
  danger: 'text-error-600',
  warning: 'text-warning-600',
  info: 'text-primary-600',
}

export function ConfirmDialog({
  isOpen,
  onClose,
  onConfirm,
  title,
  message,
  confirmText = 'Confirm',
  cancelText = 'Cancel',
  variant = 'info',
}: ConfirmDialogProps) {
  const Icon = variantIcons[variant]

  const handleConfirm = () => {
    onConfirm()
    onClose()
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      size="sm"
      showCloseButton={false}
    >
      <div className="flex items-start space-x-4">
        <div className={`flex-shrink-0 ${variantStyles[variant]}`}>
          <Icon className="h-6 w-6" />
        </div>
        
        <div className="flex-1">
          <h3 className="text-lg font-medium text-secondary-900 mb-2">
            {title}
          </h3>
          
          <p className="text-sm text-secondary-600 mb-6">
            {message}
          </p>
          
          <div className="flex items-center justify-end space-x-3">
            <Button
              variant="outline"
              onClick={onClose}
            >
              {cancelText}
            </Button>
            
            <Button
              variant={variant === 'danger' ? 'danger' : 'primary'}
              onClick={handleConfirm}
            >
              {confirmText}
            </Button>
          </div>
        </div>
      </div>
    </Modal>
  )
}