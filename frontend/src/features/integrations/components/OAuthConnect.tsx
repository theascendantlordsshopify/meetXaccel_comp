import React, { useState } from 'react'
import { ExternalLink, Shield, CheckCircle, AlertTriangle } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Modal } from '@/components/ui/Modal'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { useIntegrations } from '@/hooks/useIntegrations'

interface OAuthConnectProps {
  isOpen: boolean
  onClose: () => void
  provider: string
  integrationType: 'calendar' | 'video'
}

export function OAuthConnect({ isOpen, onClose, provider, integrationType }: OAuthConnectProps) {
  const [isConnecting, setIsConnecting] = useState(false)
  const [connectionStep, setConnectionStep] = useState<'init' | 'authorizing' | 'success' | 'error'>('init')
  const [errorMessage, setErrorMessage] = useState('')

  const { initiateOAuth } = useIntegrations()

  const handleConnect = async () => {
    setIsConnecting(true)
    setConnectionStep('authorizing')

    try {
      const result = await initiateOAuth({
        provider,
        integration_type: integrationType,
        redirect_uri: `${window.location.origin}/integrations/callback`,
      })

      // Redirect to OAuth provider
      window.location.href = result.authorization_url
    } catch (error: any) {
      setConnectionStep('error')
      setErrorMessage(error.message || 'Failed to initiate OAuth flow')
      setIsConnecting(false)
    }
  }

  const getProviderInfo = () => {
    const providers = {
      google: {
        name: 'Google',
        description: integrationType === 'calendar' 
          ? 'Connect your Google Calendar to sync events and prevent double bookings'
          : 'Connect Google Meet to automatically generate meeting links',
        permissions: integrationType === 'calendar'
          ? ['Read and write calendar events', 'Access calendar information']
          : ['Create Google Meet links', 'Access calendar for meeting scheduling'],
        color: 'bg-blue-500',
        icon: 'G',
      },
      outlook: {
        name: 'Microsoft Outlook',
        description: integrationType === 'calendar'
          ? 'Connect your Outlook Calendar to sync events and prevent double bookings'
          : 'Connect Microsoft Teams to automatically generate meeting links',
        permissions: integrationType === 'calendar'
          ? ['Read and write calendar events', 'Access calendar information']
          : ['Create Teams meetings', 'Access calendar for meeting scheduling'],
        color: 'bg-blue-600',
        icon: 'M',
      },
      zoom: {
        name: 'Zoom',
        description: 'Connect Zoom to automatically generate meeting links for your bookings',
        permissions: ['Create Zoom meetings', 'Access meeting information'],
        color: 'bg-blue-500',
        icon: 'Z',
      },
    }

    return providers[provider as keyof typeof providers] || providers.google
  }

  const providerInfo = getProviderInfo()

  const handleClose = () => {
    setConnectionStep('init')
    setErrorMessage('')
    setIsConnecting(false)
    onClose()
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title={`Connect ${providerInfo.name}`}
      size="md"
    >
      <div className="space-y-6">
        {connectionStep === 'init' && (
          <>
            <div className="text-center">
              <div className={`w-16 h-16 ${providerInfo.color} rounded-full flex items-center justify-center mx-auto mb-4`}>
                <span className="text-white text-2xl font-bold">{providerInfo.icon}</span>
              </div>
              <h3 className="text-lg font-semibold text-secondary-900 mb-2">
                Connect {providerInfo.name}
              </h3>
              <p className="text-secondary-600">
                {providerInfo.description}
              </p>
            </div>

            <div className="bg-secondary-50 p-4 rounded-lg">
              <h4 className="font-medium text-secondary-900 mb-2 flex items-center">
                <Shield className="h-4 w-4 mr-2" />
                Permissions Required
              </h4>
              <ul className="text-sm text-secondary-600 space-y-1">
                {providerInfo.permissions.map((permission, index) => (
                  <li key={index} className="flex items-center">
                    <CheckCircle className="h-3 w-3 text-success-500 mr-2" />
                    {permission}
                  </li>
                ))}
              </ul>
            </div>

            <div className="bg-info-50 border border-info-200 rounded-lg p-4">
              <h4 className="font-medium text-info-800 mb-2">What happens next?</h4>
              <ol className="text-sm text-info-700 space-y-1 list-decimal list-inside">
                <li>You'll be redirected to {providerInfo.name} to sign in</li>
                <li>Grant permissions to Calendly Clone</li>
                <li>You'll be redirected back to complete the setup</li>
                <li>Your {integrationType} will be automatically synced</li>
              </ol>
            </div>

            <div className="flex space-x-3">
              <Button type="button" variant="outline" onClick={handleClose} className="flex-1">
                Cancel
              </Button>
              <Button
                onClick={handleConnect}
                loading={isConnecting}
                disabled={isConnecting}
                className="flex-1"
                leftIcon={<ExternalLink className="h-4 w-4" />}
              >
                Connect {providerInfo.name}
              </Button>
            </div>
          </>
        )}

        {connectionStep === 'authorizing' && (
          <div className="text-center space-y-4">
            <LoadingSpinner size="lg" />
            <div>
              <h3 className="text-lg font-semibold text-secondary-900 mb-2">
                Connecting to {providerInfo.name}
              </h3>
              <p className="text-secondary-600">
                Please complete the authorization in the popup window...
              </p>
            </div>
          </div>
        )}

        {connectionStep === 'error' && (
          <div className="text-center space-y-4">
            <div className="w-16 h-16 bg-error-100 rounded-full flex items-center justify-center mx-auto">
              <AlertTriangle className="h-8 w-8 text-error-600" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-secondary-900 mb-2">
                Connection Failed
              </h3>
              <p className="text-secondary-600 mb-4">
                {errorMessage}
              </p>
              <div className="flex space-x-3">
                <Button variant="outline" onClick={handleClose} className="flex-1">
                  Close
                </Button>
                <Button onClick={handleConnect} className="flex-1">
                  Try Again
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>
    </Modal>
  )
}