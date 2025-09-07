import React, { useState } from 'react'
import { Shield, Smartphone, Key, Plus, Trash2, RefreshCw, Eye, EyeOff } from 'lucide-react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { Container } from '@/components/layout/Container'
import { Modal } from '@/components/ui/Modal'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { MFASetup } from '@/features/auth/components/MFASetup'
import { useAuth } from '@/hooks/useAuth'
import { useToggle } from '@/hooks/useToggle'
import { formatRelativeTime } from '@/utils/date'
import { z } from 'zod'

const passwordSchema = z.object({
  password: z.string().min(1, 'Password is required'),
})

type PasswordFormData = z.infer<typeof passwordSchema>

export default function MFADeviceManagement() {
  const [selectedAction, setSelectedAction] = useState<'disable' | 'regenerate' | null>(null)
  const [showMFASetup, { toggle: toggleMFASetup }] = useToggle()
  const [showPasswordModal, { toggle: togglePasswordModal }] = useToggle()
  const [showBackupCodes, { toggle: toggleBackupCodes }] = useToggle()
  const [showDisableDialog, { toggle: toggleDisableDialog }] = useToggle()
  const [newBackupCodes, setNewBackupCodes] = useState<string[]>([])
  const [showCodes, setShowCodes] = useState(false)

  const {
    user,
    mfaDevices,
    mfaDevicesLoading,
    disableMFA,
    regenerateBackupCodes,
    isMFAActionLoading,
  } = useAuth()

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<PasswordFormData>({
    resolver: zodResolver(passwordSchema),
  })

  const handleDisableMFA = () => {
    setSelectedAction('disable')
    toggleDisableDialog()
  }

  const handleRegenerateBackupCodes = () => {
    setSelectedAction('regenerate')
    togglePasswordModal()
  }

  const onPasswordSubmit = async (data: PasswordFormData) => {
    try {
      if (selectedAction === 'disable') {
        await disableMFA(data.password)
        togglePasswordModal()
        setSelectedAction(null)
      } else if (selectedAction === 'regenerate') {
        const response = await regenerateBackupCodes(data.password)
        setNewBackupCodes(response.backup_codes)
        togglePasswordModal()
        toggleBackupCodes()
        setSelectedAction(null)
      }
      reset()
    } catch (error) {
      // Error handling is done in the hook
    }
  }

  const handleClosePasswordModal = () => {
    reset()
    setSelectedAction(null)
    togglePasswordModal()
  }

  const getDeviceIcon = (deviceType: string) => {
    switch (deviceType) {
      case 'sms':
        return <Smartphone className="h-5 w-5 text-primary-600" />
      case 'backup':
        return <Key className="h-5 w-5 text-primary-600" />
      default:
        return <Shield className="h-5 w-5 text-primary-600" />
    }
  }

  const getDeviceDescription = (device: any) => {
    switch (device.device_type) {
      case 'sms':
        return `SMS to ${device.phone_number?.slice(-4).padStart(device.phone_number?.length || 0, '*')}`
      case 'backup':
        return 'Backup codes for account recovery'
      default:
        return 'Authenticator app (TOTP)'
    }
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title="Multi-Factor Authentication"
        subtitle="Secure your account with additional verification methods"
        breadcrumbs={[
          { label: 'Settings', href: '/dashboard/settings' },
          { label: 'Security', href: '/dashboard/security' },
          { label: 'MFA', current: true },
        ]}
        action={
          <div className="flex space-x-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => window.location.href = '/dashboard/security/sso'}
              leftIcon={<Shield className="h-4 w-4" />}
            >
              SSO Sessions
            </Button>
          </div>
        }
      />

      <Container>
        <div className="max-w-4xl mx-auto space-y-8">
          {/* MFA Status */}
          <Card>
            <CardHeader
              title="MFA Status"
              subtitle="Multi-factor authentication adds an extra layer of security to your account"
            />
            <CardContent>
              <div className="flex items-center justify-between p-4 bg-secondary-50 rounded-lg">
                <div className="flex items-center space-x-3">
                  <Shield className={`h-8 w-8 ${user?.is_mfa_enabled ? 'text-success-600' : 'text-secondary-400'}`} />
                  <div>
                    <p className="text-lg font-semibold text-secondary-900">
                      MFA is {user?.is_mfa_enabled ? 'Enabled' : 'Disabled'}
                    </p>
                    <p className="text-sm text-secondary-600">
                      {user?.is_mfa_enabled 
                        ? 'Your account is protected with multi-factor authentication'
                        : 'Enable MFA to add an extra layer of security'
                      }
                    </p>
                  </div>
                </div>
                <div className="flex space-x-2">
                  {user?.is_mfa_enabled ? (
                    <>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={handleRegenerateBackupCodes}
                        leftIcon={<RefreshCw className="h-4 w-4" />}
                      >
                        Regenerate Backup Codes
                      </Button>
                      <Button
                        variant="danger"
                        size="sm"
                        onClick={handleDisableMFA}
                        leftIcon={<Trash2 className="h-4 w-4" />}
                      >
                        Disable MFA
                      </Button>
                    </>
                  ) : (
                    <Button
                      onClick={toggleMFASetup}
                      leftIcon={<Plus className="h-4 w-4" />}
                    >
                      Enable MFA
                    </Button>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>

          {/* MFA Devices */}
          {user?.is_mfa_enabled && (
            <Card>
              <CardHeader
                title="MFA Devices"
                subtitle="Manage your multi-factor authentication devices"
                action={
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={toggleMFASetup}
                    leftIcon={<Plus className="h-4 w-4" />}
                  >
                    Add Device
                  </Button>
                }
              />
              <CardContent>
                {mfaDevicesLoading ? (
                  <div className="flex items-center justify-center py-8">
                    <LoadingSpinner size="lg" />
                  </div>
                ) : !mfaDevices || mfaDevices.length === 0 ? (
                  <EmptyState
                    icon={<Shield className="h-12 w-12" />}
                    title="No MFA devices"
                    description="Add your first MFA device to secure your account"
                    action={{
                      label: 'Add MFA Device',
                      onClick: toggleMFASetup,
                    }}
                  />
                ) : (
                  <div className="space-y-4">
                    {mfaDevices.map((device) => (
                      <div
                        key={device.id}
                        className="flex items-center justify-between p-4 border border-secondary-200 rounded-lg hover:border-secondary-300 transition-colors"
                      >
                        <div className="flex items-center space-x-4">
                          <div className="p-2 bg-secondary-100 rounded-lg">
                            {getDeviceIcon(device.device_type)}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center space-x-2">
                              <p className="text-sm font-medium text-secondary-900">
                                {device.name}
                              </p>
                              {device.is_primary && (
                                <Badge variant="primary" size="sm">Primary</Badge>
                              )}
                              {!device.is_active && (
                                <Badge variant="secondary" size="sm">Inactive</Badge>
                              )}
                            </div>
                            <p className="text-sm text-secondary-600">
                              {getDeviceDescription(device)}
                            </p>
                            {device.last_used_at && (
                              <p className="text-xs text-secondary-500">
                                Last used: {formatRelativeTime(device.last_used_at)}
                              </p>
                            )}
                          </div>
                        </div>
                        
                        <div className="flex items-center space-x-2">
                          {device.device_type === 'sms' && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                // TODO: Send test SMS code
                              }}
                              title="Send test code"
                            >
                              <Smartphone className="h-4 w-4" />
                            </Button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Security Tips */}
          <Card>
            <CardHeader title="Security Tips" />
            <CardContent>
              <div className="bg-info-50 border border-info-200 rounded-lg p-4">
                <h4 className="font-medium text-info-800 mb-2">Keep Your Account Secure</h4>
                <ul className="text-sm text-info-700 space-y-1 list-disc list-inside">
                  <li>Store your backup codes in a safe place separate from your authenticator device</li>
                  <li>Don't share your backup codes with anyone</li>
                  <li>Regenerate backup codes if you suspect they've been compromised</li>
                  <li>Keep your authenticator app updated and synchronized</li>
                  <li>Consider setting up multiple MFA methods for redundancy</li>
                </ul>
              </div>
            </CardContent>
          </Card>
        </div>
      </Container>

      {/* MFA Setup Modal */}
      <MFASetup isOpen={showMFASetup} onClose={toggleMFASetup} />

      {/* Password Confirmation Modal */}
      <Modal
        isOpen={showPasswordModal}
        onClose={handleClosePasswordModal}
        title="Confirm Password"
        size="sm"
      >
        <form onSubmit={handleSubmit(onPasswordSubmit)} className="space-y-6">
          <div className="text-center">
            <Shield className="h-12 w-12 text-warning-600 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-secondary-900 mb-2">
              Security Verification Required
            </h3>
            <p className="text-sm text-secondary-600">
              Please enter your password to {selectedAction === 'disable' ? 'disable MFA' : 'regenerate backup codes'}
            </p>
          </div>

          <Input
            {...register('password')}
            type="password"
            label="Current Password"
            placeholder="Enter your password"
            error={errors.password?.message}
            autoFocus
            required
          />

          <div className="flex space-x-3">
            <Button
              type="button"
              variant="outline"
              onClick={handleClosePasswordModal}
              className="flex-1"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              loading={isMFAActionLoading}
              disabled={isMFAActionLoading}
              className="flex-1"
              variant={selectedAction === 'disable' ? 'danger' : 'primary'}
            >
              {selectedAction === 'disable' ? 'Disable MFA' : 'Regenerate Codes'}
            </Button>
          </div>
        </form>
      </Modal>

      {/* Backup Codes Display Modal */}
      <Modal
        isOpen={showBackupCodes}
        onClose={toggleBackupCodes}
        title="New Backup Codes"
        size="md"
      >
        <div className="space-y-6">
          <div className="text-center">
            <Key className="h-12 w-12 text-success-600 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-secondary-900 mb-2">
              Your New Backup Codes
            </h3>
            <p className="text-sm text-secondary-600">
              Save these codes in a secure location. Each code can only be used once.
            </p>
          </div>

          <div className="bg-warning-50 border border-warning-200 rounded-lg p-4">
            <h4 className="font-medium text-warning-800 mb-2">Important</h4>
            <ul className="text-sm text-warning-700 space-y-1 list-disc list-inside">
              <li>These codes replace your previous backup codes</li>
              <li>Store them in a password manager or secure location</li>
              <li>Each code can only be used once</li>
              <li>Don't share these codes with anyone</li>
            </ul>
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="font-medium text-secondary-900">Backup Codes</h4>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowCodes(!showCodes)}
                leftIcon={showCodes ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              >
                {showCodes ? 'Hide' : 'Show'} Codes
              </Button>
            </div>
            
            {showCodes && (
              <div className="grid grid-cols-2 gap-2">
                {newBackupCodes.map((code, index) => (
                  <div
                    key={index}
                    className="bg-white p-3 rounded border font-mono text-sm text-center cursor-pointer hover:bg-secondary-50 transition-colors"
                    onClick={() => navigator.clipboard.writeText(code)}
                    title="Click to copy"
                  >
                    {code}
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="flex justify-center">
            <Button onClick={toggleBackupCodes}>
              I've Saved These Codes
            </Button>
          </div>
        </div>
      </Modal>

      {/* Disable MFA Confirmation */}
      <ConfirmDialog
        isOpen={showDisableDialog}
        onClose={toggleDisableDialog}
        onConfirm={() => {
          toggleDisableDialog()
          togglePasswordModal()
        }}
        title="Disable Multi-Factor Authentication"
        message="Are you sure you want to disable MFA? This will make your account less secure. You'll need to enter your password to confirm."
        confirmText="Continue"
        variant="warning"
      />
    </div>
  )
}