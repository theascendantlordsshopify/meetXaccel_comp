import React, { useEffect } from 'react'
import { Link, useSearchParams, Navigate } from 'react-router-dom'
import { Calendar, Check, X, Mail } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent } from '@/components/ui/Card'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { useAuth } from '@/hooks/useAuth'
import { ROUTES } from '@/constants/routes'

export default function VerifyEmail() {
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token')
  const { verifyEmail, isEmailVerificationLoading, resendVerification, user, clearError } = useAuth()
  const [verificationStatus, setVerificationStatus] = React.useState<'loading' | 'success' | 'error'>('loading')

  // Clear any previous errors when component mounts
  React.useEffect(() => {
    clearError()
  }, [clearError])

  useEffect(() => {
    if (token) {
      verifyEmail({ token })
        .then(() => setVerificationStatus('success'))
        .catch(() => setVerificationStatus('error'))
    } else {
      setVerificationStatus('error')
    }
  }, [token, verifyEmail])

  if (!token) {
    return <Navigate to={ROUTES.LOGIN} replace />
  }

  if (verificationStatus === 'loading') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary-50 to-secondary-100">
        <div className="text-center">
          <LoadingSpinner size="lg" />
          <p className="mt-4 text-secondary-600">Verifying your email...</p>
        </div>
      </div>
    )
  }

  if (verificationStatus === 'success') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary-50 to-secondary-100 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8">
          <div className="text-center">
            <div className="flex justify-center">
              <div className="rounded-full bg-success-100 p-3">
                <Check className="h-8 w-8 text-success-600" />
              </div>
            </div>
            <h2 className="mt-6 text-3xl font-bold text-secondary-900">
              Email verified!
            </h2>
            <p className="mt-2 text-sm text-secondary-600">
              Your email has been successfully verified. You can now access all features.
            </p>
          </div>

          <Card>
            <CardContent className="p-6 text-center">
              <Link to={user ? ROUTES.DASHBOARD : ROUTES.LOGIN}>
                <Button fullWidth>
                  {user ? 'Go to Dashboard' : 'Continue to Sign In'}
                </Button>
              </Link>
            </CardContent>
          </Card>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary-50 to-secondary-100 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div className="text-center">
          <div className="flex justify-center">
            <div className="rounded-full bg-error-100 p-3">
              <X className="h-8 w-8 text-error-600" />
            </div>
          </div>
          <h2 className="mt-6 text-3xl font-bold text-secondary-900">
            Verification failed
          </h2>
          <p className="mt-2 text-sm text-secondary-600">
            The verification link is invalid or has expired.
          </p>
        </div>

        <Card>
          <CardContent className="p-6">
            <div className="text-center space-y-4">
              <p className="text-sm text-secondary-600">
                Need a new verification link?
              </p>
              
              <Button
                variant="outline"
                fullWidth
                onClick={() => {
                  const email = prompt('Enter your email address:')
                  if (email) {
                    resendVerification(email)
                  }
                }}
                leftIcon={<Mail className="h-4 w-4" />}
              >
                Resend verification email
              </Button>
              
              <Link to={ROUTES.LOGIN}>
                <Button variant="ghost" fullWidth>
                  Back to sign in
                </Button>
              </Link>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}