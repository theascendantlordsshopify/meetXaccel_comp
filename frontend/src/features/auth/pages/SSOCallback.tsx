import React, { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Shield, CheckCircle, XCircle, AlertTriangle } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { useAuth } from '@/hooks/useAuth'
import { ROUTES } from '@/constants/routes'

export default function SSOCallback() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const [status, setStatus] = useState<'processing' | 'success' | 'error'>('processing')
  const [errorMessage, setErrorMessage] = useState('')
  
  const { handleSSOCallback, isSSOActionLoading } = useAuth()

  useEffect(() => {
    const processCallback = async () => {
      try {
        // Extract parameters from URL
        const code = searchParams.get('code')
        const state = searchParams.get('state')
        const samlResponse = searchParams.get('SAMLResponse')
        const relayState = searchParams.get('RelayState')
        
        // Determine SSO type based on available parameters
        let ssoType: 'saml' | 'oidc'
        let callbackData: any = {}
        
        if (samlResponse) {
          // SAML callback
          ssoType = 'saml'
          callbackData = {
            sso_type: 'saml',
            saml_response: samlResponse,
            relay_state: relayState,
          }
        } else if (code) {
          // OIDC callback
          ssoType = 'oidc'
          callbackData = {
            sso_type: 'oidc',
            code,
            state,
          }
        } else {
          throw new Error('Invalid SSO callback parameters')
        }
        
        // Process the callback
        await handleSSOCallback(callbackData)
        
        setStatus('success')
        
        // Redirect to dashboard after a brief delay
        setTimeout(() => {
          navigate(ROUTES.DASHBOARD)
        }, 2000)
        
      } catch (error: any) {
        console.error('SSO callback error:', error)
        setStatus('error')
        setErrorMessage(error.message || 'SSO authentication failed')
      }
    }

    processCallback()
  }, [searchParams, handleSSOCallback, navigate])

  const getStatusIcon = () => {
    switch (status) {
      case 'processing':
        return <LoadingSpinner size="lg" />
      case 'success':
        return (
          <div className="w-16 h-16 bg-success-100 rounded-full flex items-center justify-center">
            <CheckCircle className="h-8 w-8 text-success-600" />
          </div>
        )
      case 'error':
        return (
          <div className="w-16 h-16 bg-error-100 rounded-full flex items-center justify-center">
            <XCircle className="h-8 w-8 text-error-600" />
          </div>
        )
      default:
        return null
    }
  }

  const getStatusMessage = () => {
    switch (status) {
      case 'processing':
        return {
          title: 'Processing SSO Authentication',
          description: 'Please wait while we complete your sign-in...',
        }
      case 'success':
        return {
          title: 'SSO Authentication Successful',
          description: 'You have been signed in successfully. Redirecting to dashboard...',
        }
      case 'error':
        return {
          title: 'SSO Authentication Failed',
          description: errorMessage || 'There was an error processing your SSO authentication.',
        }
      default:
        return { title: '', description: '' }
    }
  }

  const statusMessage = getStatusMessage()

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary-50 to-secondary-100 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full">
        <Card>
          <CardContent className="p-8 text-center">
            <div className="flex justify-center mb-6">
              {getStatusIcon()}
            </div>
            
            <h1 className="text-2xl font-bold text-secondary-900 mb-4">
              {statusMessage.title}
            </h1>
            
            <p className="text-secondary-600 mb-6">
              {statusMessage.description}
            </p>
            
            {status === 'error' && (
              <div className="space-y-4">
                <div className="bg-error-50 border border-error-200 rounded-lg p-4">
                  <div className="flex items-center space-x-2">
                    <AlertTriangle className="h-4 w-4 text-error-500" />
                    <p className="text-sm font-medium text-error-800">What went wrong?</p>
                  </div>
                  <p className="text-sm text-error-700 mt-1">
                    {errorMessage}
                  </p>
                </div>
                
                <div className="flex space-x-3">
                  <Button
                    variant="outline"
                    onClick={() => navigate(ROUTES.LOGIN)}
                    className="flex-1"
                  >
                    Back to Login
                  </Button>
                  <Button
                    onClick={() => window.location.reload()}
                    className="flex-1"
                  >
                    Try Again
                  </Button>
                </div>
              </div>
            )}
            
            {status === 'processing' && (
              <div className="bg-info-50 border border-info-200 rounded-lg p-4">
                <p className="text-sm text-info-700">
                  This may take a few moments. Please do not close this window.
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}