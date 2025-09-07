import React from 'react'
import { Link } from 'react-router-dom'
import { ArrowLeft, Calendar, Mail } from 'lucide-react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Card, CardContent } from '@/components/ui/Card'
import { useAuth } from '@/hooks/useAuth'
import { ROUTES } from '@/constants/routes'
import { passwordResetRequestSchema, type PasswordResetRequestFormData } from '@/types/forms'

export default function ForgotPassword() {
  const { requestPasswordReset, isPasswordResetLoading, clearError } = useAuth()

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitted },
  } = useForm<PasswordResetRequestFormData>({
    resolver: zodResolver(passwordResetRequestSchema),
  })

  // Clear any previous errors when component mounts
  React.useEffect(() => {
    clearError()
  }, [clearError])

  const onSubmit = (data: PasswordResetRequestFormData) => {
    requestPasswordReset(data)
  }

  if (isSubmitted && !isPasswordResetLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary-50 to-secondary-100 px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8">
          <div className="text-center">
            <div className="flex justify-center">
              <div className="rounded-full bg-success-100 p-3">
                <Mail className="h-8 w-8 text-success-600" />
              </div>
            </div>
            <h2 className="mt-6 text-3xl font-bold text-secondary-900">
              Check your email
            </h2>
            <p className="mt-2 text-sm text-secondary-600">
              We've sent a password reset link to your email address.
            </p>
          </div>

          <Card>
            <CardContent className="p-6 text-center">
              <p className="text-sm text-secondary-600 mb-6">
                Didn't receive the email? Check your spam folder or try again.
              </p>
              
              <div className="space-y-3">
                <Button
                  variant="outline"
                  fullWidth
                  onClick={() => window.location.reload()}
                >
                  Try again
                </Button>
                
                <Link to={ROUTES.LOGIN}>
                  <Button variant="ghost" fullWidth>
                    <ArrowLeft className="h-4 w-4 mr-2" />
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

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary-50 to-secondary-100 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        {/* Header */}
        <div className="text-center">
          <div className="flex justify-center">
            <Calendar className="h-12 w-12 text-primary-600" />
          </div>
          <h2 className="mt-6 text-3xl font-bold text-secondary-900">
            Reset your password
          </h2>
          <p className="mt-2 text-sm text-secondary-600">
            Enter your email address and we'll send you a link to reset your password
          </p>
        </div>

        {/* Reset Form */}
        <Card>
          <CardContent className="p-6">
            <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
              <Input
                {...register('email')}
                type="email"
                label="Email address"
                placeholder="Enter your email"
                error={errors.email?.message}
                autoComplete="email"
                autoFocus
              />

              <Button
                type="submit"
                fullWidth
                loading={isPasswordResetLoading}
                disabled={isPasswordResetLoading}
              >
                Send reset link
              </Button>
            </form>

            <div className="mt-6 text-center">
              <Link
                to={ROUTES.LOGIN}
                className="inline-flex items-center text-sm text-primary-600 hover:text-primary-500 transition-colors"
              >
                <ArrowLeft className="h-4 w-4 mr-1" />
                Back to sign in
              </Link>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}