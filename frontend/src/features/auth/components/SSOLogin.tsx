import React, { useState } from 'react'
import { Building, ArrowRight, Globe } from 'lucide-react'
import { useForm } from 'react-hook-form'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Modal } from '@/components/ui/Modal'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'

interface SSOLoginProps {
  isOpen: boolean
  onClose: () => void
}

interface SSODiscoveryForm {
  domain: string
}

interface SSOProvider {
  type: 'saml' | 'oidc'
  organization: string
  domain: string
}

export function SSOLogin({ isOpen, onClose }: SSOLoginProps) {
  const [step, setStep] = useState<'discovery' | 'providers' | 'redirecting'>('discovery')
  const [providers, setProviders] = useState<SSOProvider[]>([])
  const [isLoading, setIsLoading] = useState(false)

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<SSODiscoveryForm>()

  const onDiscovery = async (data: SSODiscoveryForm) => {
    setIsLoading(true)
    try {
      const response = await authService.ssoDiscovery(data.domain)
      setProviders(response.providers)
      setStep('providers')
    } catch (error) {
      console.error('SSO discovery failed:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const onSelectProvider = async (provider: SSOProvider) => {
    setStep('redirecting')
    try {
      const response = await authService.initiatSSO({
        sso_type: provider.type,
        organization_domain: provider.domain,
        redirect_url: window.location.origin + '/dashboard'
      })
      
      // Redirect to the SSO provider
      window.location.href = response.auth_url
    } catch (error) {
      console.error('SSO initiation failed:', error)
      setStep('providers')
    }
  }

  const handleClose = () => {
    setStep('discovery')
    setProviders([])
    setIsLoading(false)
    onClose()
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title="Sign in with SSO"
      size="md"
    >
      {step === 'discovery' && (
        <div className="space-y-6">
          <div className="text-center">
            <Building className="h-12 w-12 text-primary-600 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-secondary-900 mb-2">
              Enterprise Sign-In
            </h3>
            <p className="text-sm text-secondary-600">
              Enter your organization's domain to find available sign-in options.
            </p>
          </div>

          <form onSubmit={handleSubmit(onDiscovery)} className="space-y-4">
            <Input
              {...register('domain', { required: 'Domain is required' })}
              label="Organization domain"
              placeholder="company.com"
              error={errors.domain?.message}
              autoFocus
              leftIcon={<Globe className="h-4 w-4" />}
            />

            <div className="flex space-x-3">
              <Button type="button" variant="outline" onClick={handleClose} className="flex-1">
                Cancel
              </Button>
              <Button type="submit" loading={isLoading} className="flex-1">
                Continue
              </Button>
            </div>
          </form>
        </div>
      )}

      {step === 'providers' && (
        <div className="space-y-6">
          <div className="text-center">
            <Building className="h-12 w-12 text-primary-600 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-secondary-900 mb-2">
              Choose Sign-In Method
            </h3>
            <p className="text-sm text-secondary-600">
              Select how you'd like to sign in to your organization.
            </p>
          </div>

          <div className="space-y-3">
            {providers.map((provider, index) => (
              <button
                key={index}
                onClick={() => onSelectProvider(provider)}
                className="w-full p-4 border-2 border-secondary-200 rounded-lg hover:border-primary-300 hover:bg-primary-50 transition-colors text-left"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <div className="font-medium text-secondary-900">
                      {provider.organization}
                    </div>
                    <div className="text-sm text-secondary-600">
                      {provider.domain}
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Badge variant="secondary" size="sm">
                      {provider.type.toUpperCase()}
                    </Badge>
                    <ArrowRight className="h-4 w-4 text-secondary-400" />
                  </div>
                </div>
              </button>
            ))}
          </div>

          <Button variant="outline" onClick={() => setStep('discovery')} fullWidth>
            Try different domain
          </Button>
        </div>
      )}

      {step === 'redirecting' && (
        <div className="space-y-6 text-center">
          <LoadingSpinner size="lg" />
          <div>
            <h3 className="text-lg font-semibold text-secondary-900 mb-2">
              Redirecting to your organization
            </h3>
            <p className="text-sm text-secondary-600">
              Please wait while we redirect you to your organization's sign-in page.
            </p>
          </div>
        </div>
      )}
    </Modal>
  )
}