import React, { useState } from 'react'
import { QrCode, Smartphone, Shield, Copy, Check } from 'lucide-react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Modal } from '@/components/ui/Modal'
import { Badge } from '@/components/ui/Badge'
import { useAuth } from '@/hooks/useAuth'
import { copyToClipboard } from '@/utils/helpers'
import { mfaSetupSchema, mfaVerificationSchema, type MFASetupFormData, type MFAVerificationFormData } from '@/types/forms'

interface MFASetupProps {
  isOpen: boolean
  onClose: () => void
}

export function MFASetup({ isOpen, onClose }: MFASetupProps) {
  const [step, setStep] = useState<'setup' | 'verify' | 'complete'>('setup')
  const [setupData, setSetupData] = useState<any>(null)
  const [deviceType, setDeviceType] = useState<'totp' | 'sms'>('totp')
  const [copiedSecret, setCopiedSecret] = useState(false)
  const { setupMFA, verifyMFASetup, verifySMSMFASetup, resendSMSOTP } = useAuth()

  const setupForm = useForm<MFASetupFormData>({
    resolver: zodResolver(mfaSetupSchema),
    defaultValues: {
      device_type: 'totp',
      device_name: 'Authenticator App',
    },
  })

  const verifyForm = useForm<MFAVerificationFormData>({
    resolver: zodResolver(mfaVerificationSchema),
  })

  const onSetup = async (data: MFASetupFormData) => {
    try {
      setDeviceType(data.device_type as 'totp' | 'sms')
      const result = await setupMFA({
        device_type: data.device_type,
        device_name: data.device_name,
        phone_number: data.phone_number,
      })
      setSetupData({ ...result, device_type: data.device_type })
      setStep('verify')
    } catch (error) {
      console.error('MFA setup failed:', error)
    }
  }

  const onVerify = async (data: MFAVerificationFormData) => {
    try {
      let result
      if (deviceType === 'sms') {
        result = await verifySMSMFASetup({
          otp_code: data.otp_code,
          device_id: setupData?.device_id,
        })
      } else {
        result = await verifyMFASetup({
          otp_code: data.otp_code,
        })
      }
      setSetupData(result)
      setStep('complete')
    } catch (error) {
      console.error('MFA verification failed:', error)
    }
  }

  const handleCopySecret = async () => {
    if (setupData?.manual_entry_key) {
      const success = await copyToClipboard(setupData.manual_entry_key)
      if (success) {
        setCopiedSecret(true)
        setTimeout(() => setCopiedSecret(false), 2000)
      }
    }
  }

  const handleClose = () => {
    setStep('setup')
    setSetupData(null)
    setDeviceType('totp')
    setCopiedSecret(false)
    setupForm.reset()
    verifyForm.reset()
    onClose()
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title="Set up Multi-Factor Authentication"
      size="md"
    >
      {step === 'setup' && (
        <form onSubmit={setupForm.handleSubmit(onSetup)} className="space-y-6">
          <div className="text-center">
            <Shield className="h-12 w-12 text-primary-600 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-secondary-900 mb-2">
              Secure your account
            </h3>
            <p className="text-sm text-secondary-600">
              Add an extra layer of security to your account with multi-factor authentication.
            </p>
          </div>

          <div className="space-y-4">
            <div className="grid grid-cols-1 gap-3">
              <label className="relative">
                <input
                  {...setupForm.register('device_type')}
                  type="radio"
                  value="totp"
                  className="sr-only peer"
                />
                <div className="p-4 border-2 border-secondary-200 rounded-lg cursor-pointer peer-checked:border-primary-500 peer-checked:bg-primary-50 hover:border-secondary-300 transition-colors">
                  <div className="flex items-center space-x-3">
                    <QrCode className="h-6 w-6 text-primary-600" />
                    <div>
                      <div className="font-medium text-secondary-900">Authenticator App</div>
                      <div className="text-sm text-secondary-600">Use Google Authenticator, Authy, or similar</div>
                    </div>
                    <Badge variant="primary" size="sm">Recommended</Badge>
                  </div>
                </div>
              </label>

              <label className="relative">
                <input
                  {...setupForm.register('device_type')}
                  type="radio"
                  value="sms"
                  className="sr-only peer"
                />
                <div className="p-4 border-2 border-secondary-200 rounded-lg cursor-pointer peer-checked:border-primary-500 peer-checked:bg-primary-50 hover:border-secondary-300 transition-colors">
                  <div className="flex items-center space-x-3">
                    <Smartphone className="h-6 w-6 text-primary-600" />
                    <div>
                      <div className="font-medium text-secondary-900">SMS</div>
                      <div className="text-sm text-secondary-600">Receive codes via text message</div>
                    </div>
                  </div>
                </div>
              </label>
            </div>

            <Input
              {...setupForm.register('device_name')}
              label="Device name"
              placeholder="My iPhone, Work Computer, etc."
              error={setupForm.formState.errors.device_name?.message}
            />

            {setupForm.watch('device_type') === 'sms' && (
              <Input
                {...setupForm.register('phone_number')}
                type="tel"
                label="Phone number"
                placeholder="+1 (555) 123-4567"
              />
            )}
          </div>

          <div className="flex space-x-3">
            <Button type="button" variant="outline" onClick={handleClose} className="flex-1">
              Cancel
            </Button>
            <Button type="submit" className="flex-1">
              Continue
            </Button>
          </div>
        </form>
      )}

      {step === 'verify' && setupData && (
        <div className="space-y-6">
          {deviceType === 'totp' ? (
            <>
              <div className="text-center">
                <QrCode className="h-12 w-12 text-primary-600 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-secondary-900 mb-2">
                  Scan QR Code
                </h3>
                <p className="text-sm text-secondary-600">
                  Scan this QR code with your authenticator app, then enter the verification code.
                </p>
              </div>

              {setupData.qr_code && (
                <div className="flex justify-center">
                  <img
                    src={setupData.qr_code}
                    alt="QR Code"
                    className="w-48 h-48 border border-secondary-200 rounded-lg"
                  />
                </div>
              )}

              {setupData.manual_entry_key && (
                <div className="bg-secondary-50 p-4 rounded-lg">
                  <p className="text-sm font-medium text-secondary-900 mb-2">
                    Can't scan? Enter this code manually:
                  </p>
                  <div className="flex items-center space-x-2">
                    <code className="flex-1 text-sm bg-white px-3 py-2 rounded border font-mono">
                      {setupData.manual_entry_key}
                    </code>
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={handleCopySecret}
                    >
                      {copiedSecret ? (
                        <Check className="h-4 w-4" />
                      ) : (
                        <Copy className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                </div>
              )}
            </>
          ) : (
            <>
              <div className="text-center">
                <Smartphone className="h-12 w-12 text-primary-600 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-secondary-900 mb-2">
                  Enter SMS Code
                </h3>
                <p className="text-sm text-secondary-600">
                  We've sent a verification code to {setupData.phone_number}. Enter it below to complete setup.
                </p>
              </div>

              <div className="bg-info-50 border border-info-200 rounded-lg p-4">
                <h4 className="font-medium text-info-800 mb-2">Didn't receive the code?</h4>
                <p className="text-sm text-info-700 mb-3">
                  Check your messages or wait a moment for the SMS to arrive.
                </p>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => resendSMSOTP()}
                  leftIcon={<Smartphone className="h-4 w-4" />}
                >
                  Resend SMS Code
                </Button>
              </div>
            </>
          )}

          <form onSubmit={verifyForm.handleSubmit(onVerify)} className="space-y-4">
            <Input
              {...verifyForm.register('otp_code')}
              label="Verification code"
              placeholder="Enter 6-digit code"
              error={verifyForm.formState.errors.otp_code?.message}
              autoFocus
              maxLength={6}
            />

            <div className="flex space-x-3">
              <Button type="button" variant="outline" onClick={handleClose} className="flex-1">
                Cancel
              </Button>
              <Button type="submit" className="flex-1">
                Verify & Enable
              </Button>
            </div>
          </form>
        </div>
      )}

      {step === 'complete' && setupData && (
        <div className="space-y-6">
          <div className="text-center">
            <div className="flex justify-center">
              <div className="rounded-full bg-success-100 p-3">
                <Check className="h-8 w-8 text-success-600" />
              </div>
            </div>
            <h3 className="text-lg font-semibold text-secondary-900 mb-2">
              MFA Enabled Successfully!
            </h3>
            <p className="text-sm text-secondary-600">
              Your account is now protected with multi-factor authentication.
            </p>
          </div>

          {setupData.backup_codes && (
            <div className="bg-warning-50 border border-warning-200 rounded-lg p-4">
              <h4 className="font-medium text-warning-800 mb-2">
                Save your backup codes
              </h4>
              <p className="text-sm text-warning-700 mb-3">
                Store these codes in a safe place. You can use them to access your account if you lose your authenticator device.
              </p>
              <div className="grid grid-cols-2 gap-2 font-mono text-sm">
                {setupData.backup_codes.map((code: string, index: number) => (
                  <div key={index} className="bg-white px-2 py-1 rounded border text-center">
                    {code}
                  </div>
                ))}
              </div>
            </div>
          )}

          <Button onClick={handleClose} fullWidth>
            Done
          </Button>
        </div>
      )}
    </Modal>
  )
}