import React, { useState } from 'react'
import { Shield, Smartphone, Key, RefreshCw, ArrowLeft } from 'lucide-react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Modal } from '@/components/ui/Modal'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { useAuth } from '@/hooks/useAuth'
import { mfaVerificationSchema, type MFAVerificationFormData } from '@/types/forms'
import type { MFADevice } from '@/types'

interface MFALoginPromptProps {
  isOpen: boolean
  onClose: () => void
  onSuccess: () => void
}

interface BackupCodeForm {
  backup_code: string
}

const backupCodeSchema = z.object({
  backup_code: z.string().min(1, 'Backup code is required'),
})

export function MFALoginPrompt({ isOpen, onClose, onSuccess }: MFALoginPromptProps) {
  const [verificationMethod, setVerificationMethod] = useState<'totp' | 'sms' | 'backup'>('totp')
  const [selectedDevice, setSelectedDevice] = useState<MFADevice | null>(null)
  
  const { 
    mfaDevices, 
    mfaDevicesLoading, 
    sendSMSMFACode, 
    verifyMFALogin, 
    verifyBackupCode,
    isMFAActionLoading 
  } = useAuth()

  const otpForm = useForm<MFAVerificationFormData>({
    resolver: zodResolver(mfaVerificationSchema),
  })

  const backupForm = useForm<BackupCodeForm>({
    resolver: zodResolver(backupCodeSchema),
  })

  // Set default device when devices load
  React.useEffect(() => {
    if (mfaDevices && mfaDevices.length > 0 && !selectedDevice) {
      const primaryDevice = mfaDevices.find(d => d.is_primary) || mfaDevices[0]
      setSelectedDevice(primaryDevice)
      setVerificationMethod(primaryDevice.device_type as 'totp' | 'sms')
    }
  }, [mfaDevices, selectedDevice])

  const onVerifyOTP = async (data: MFAVerificationFormData) => {
    try {
      await verifyMFALogin({
        otp_code: data.otp_code,
        device_id: selectedDevice?.id,
      })
      onSuccess()
    } catch (error) {
      // Error handling is done in the hook
    }
  }

  const onVerifyBackup = async (data: BackupCodeForm) => {
    try {
      await verifyBackupCode({
        backup_code: data.backup_code,
      })
      onSuccess()
    } catch (error) {
      // Error handling is done in the hook
    }
  }

  const handleSendSMSCode = () => {
    if (selectedDevice && selectedDevice.device_type === 'sms') {
      sendSMSMFACode(selectedDevice.id)
    }
  }

  const handleDeviceChange = (device: MFADevice) => {
    setSelectedDevice(device)
    setVerificationMethod(device.device_type as 'totp' | 'sms')
    // Reset forms when switching devices
    otpForm.reset()
    backupForm.reset()
  }

  const handleClose = () => {
    setVerificationMethod('totp')
    setSelectedDevice(null)
    otpForm.reset()
    backupForm.reset()
    onClose()
  }

  if (mfaDevicesLoading) {
    return (
      <Modal isOpen={isOpen} onClose={handleClose} title="Multi-Factor Authentication" size="md">
        <div className="flex items-center justify-center py-8">
          <LoadingSpinner size="lg" />
        </div>
      </Modal>
    )
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title="Multi-Factor Authentication"
      size="md"
      closeOnOverlayClick={false}
      closeOnEscape={false}
    >
      <div className="space-y-6">
        <div className="text-center">
          <Shield className="h-12 w-12 text-primary-600 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-secondary-900 mb-2">
            Verify Your Identity
          </h3>
          <p className="text-sm text-secondary-600">
            Enter your verification code to complete sign in
          </p>
        </div>

        {/* Device Selection */}
        {mfaDevices && mfaDevices.length > 1 && (
          <div>
            <label className="block text-sm font-medium text-secondary-700 mb-2">
              Choose verification method:
            </label>
            <div className="space-y-2">
              {mfaDevices.map((device) => (
                <label key={device.id} className="relative">
                  <input
                    type="radio"
                    name="mfaDevice"
                    checked={selectedDevice?.id === device.id}
                    onChange={() => handleDeviceChange(device)}
                    className="sr-only peer"
                  />
                  <div className="p-3 border-2 border-secondary-200 rounded-lg cursor-pointer peer-checked:border-primary-500 peer-checked:bg-primary-50 hover:border-secondary-300 transition-colors">
                    <div className="flex items-center space-x-3">
                      {device.device_type === 'sms' ? (
                        <Smartphone className="h-5 w-5 text-primary-600" />
                      ) : (
                        <Shield className="h-5 w-5 text-primary-600" />
                      )}
                      <div className="flex-1">
                        <div className="font-medium text-secondary-900">{device.name}</div>
                        <div className="text-sm text-secondary-600">
                          {device.device_type === 'sms' 
                            ? `SMS to ${device.phone_number?.slice(-4).padStart(device.phone_number?.length || 0, '*')}`
                            : 'Authenticator App'
                          }
                        </div>
                      </div>
                      {device.is_primary && (
                        <Badge variant="primary" size="sm">Primary</Badge>
                      )}
                    </div>
                  </div>
                </label>
              ))}
            </div>
          </div>
        )}

        {/* Verification Form */}
        {verificationMethod !== 'backup' ? (
          <form onSubmit={otpForm.handleSubmit(onVerifyOTP)} className="space-y-4">
            {verificationMethod === 'sms' && (
              <div className="bg-info-50 border border-info-200 rounded-lg p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-info-800">
                      SMS code sent to {selectedDevice?.phone_number}
                    </p>
                    <p className="text-xs text-info-600">
                      Enter the 6-digit code from your text message
                    </p>
                  </div>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={handleSendSMSCode}
                    disabled={isMFAActionLoading}
                    leftIcon={<RefreshCw className="h-4 w-4" />}
                  >
                    Resend
                  </Button>
                </div>
              </div>
            )}

            <Input
              {...otpForm.register('otp_code')}
              label={verificationMethod === 'sms' ? 'SMS Code' : 'Authenticator Code'}
              placeholder="Enter 6-digit code"
              error={otpForm.formState.errors.otp_code?.message}
              autoFocus
              maxLength={6}
              className="text-center text-lg tracking-widest"
            />

            <div className="flex space-x-3">
              <Button
                type="button"
                variant="outline"
                onClick={() => setVerificationMethod('backup')}
                className="flex-1"
                leftIcon={<Key className="h-4 w-4" />}
              >
                Use Backup Code
              </Button>
              <Button
                type="submit"
                loading={isMFAActionLoading}
                disabled={isMFAActionLoading}
                className="flex-1"
              >
                Verify
              </Button>
            </div>
          </form>
        ) : (
          <form onSubmit={backupForm.handleSubmit(onVerifyBackup)} className="space-y-4">
            <div className="bg-warning-50 border border-warning-200 rounded-lg p-4">
              <h4 className="font-medium text-warning-800 mb-2">Using Backup Code</h4>
              <p className="text-sm text-warning-700">
                Enter one of your backup codes. Each code can only be used once.
              </p>
            </div>

            <Input
              {...backupForm.register('backup_code')}
              label="Backup Code"
              placeholder="Enter backup code"
              error={backupForm.formState.errors.backup_code?.message}
              autoFocus
              className="text-center text-lg tracking-widest font-mono"
            />

            <div className="flex space-x-3">
              <Button
                type="button"
                variant="outline"
                onClick={() => setVerificationMethod(selectedDevice?.device_type as 'totp' | 'sms' || 'totp')}
                className="flex-1"
                leftIcon={<ArrowLeft className="h-4 w-4" />}
              >
                Back to {selectedDevice?.device_type === 'sms' ? 'SMS' : 'Authenticator'}
              </Button>
              <Button
                type="submit"
                loading={isMFAActionLoading}
                disabled={isMFAActionLoading}
                className="flex-1"
              >
                Verify Backup Code
              </Button>
            </div>
          </form>
        )}

        {verificationMethod === 'totp' && (
          <div className="bg-secondary-50 p-4 rounded-lg">
            <h4 className="font-medium text-secondary-900 mb-2">Having trouble?</h4>
            <ul className="text-sm text-secondary-600 space-y-1 list-disc list-inside">
              <li>Make sure your device's time is synchronized</li>
              <li>Try refreshing your authenticator app</li>
              <li>Use a backup code if you can't access your authenticator</li>
            </ul>
          </div>
        )}
      </div>
    </Modal>
  )
}