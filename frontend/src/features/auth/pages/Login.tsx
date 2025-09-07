import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { Eye, EyeOff, Calendar, Building } from 'lucide-react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Checkbox } from '@/components/ui/Checkbox'
import { Card, CardContent } from '@/components/ui/Card'
import { SSOLogin } from '@/features/auth/components/SSOLogin'
import { MFALoginPrompt } from '@/features/auth/components/MFALoginPrompt'
import { useAuth } from '@/hooks/useAuth'
import { useToggle } from '@/hooks/useToggle'
import { ROUTES } from '@/constants/routes'
import { loginSchema, type LoginFormData } from '@/types/forms'

export default function Login() {
  const [showPassword, setShowPassword] = useState(false)
  const [showSSOModal, { toggle: toggleSSOModal }] = useToggle()
  const [showMFAPrompt, { toggle: toggleMFAPrompt }] = useToggle()
  const [pendingMFAUser, setPendingMFAUser] = useState<any>(null)
  const { login, isLoginLoading, error } = useAuth()

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      remember_me: false,
    },
  })

  const onSubmit = (data: LoginFormData) => {
    login(data.email, data.password, data.remember_me)
      .then((response: any) => {
        // Check if MFA is required
        if (response?.user?.is_mfa_enabled && !response?.mfa_verified) {
          setPendingMFAUser(response.user)
          toggleMFAPrompt()
        }
        // If MFA is not required or already verified, navigation will be handled by the auth store
      })
      .catch(() => {
        // Error handling is done in the hook
      })
  }

  const handleMFASuccess = () => {
    setPendingMFAUser(null)
    toggleMFAPrompt()
    // Navigation to dashboard will be handled by the auth store
  }

  const handleMFACancel = () => {
    setPendingMFAUser(null)
    toggleMFAPrompt()
    // User remains on login page
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
            Welcome back
          </h2>
          <p className="mt-2 text-sm text-secondary-600">
            Sign in to your account to continue
          </p>
        </div>

        {/* Login Form */}
        <Card>
          <CardContent className="p-6">
            <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
              {/* Global Error Display */}
              {error && (
                <div className="bg-error-50 border border-error-200 rounded-lg p-4">
                  <p className="text-sm text-error-700">{error}</p>
                </div>
              )}

              <Input
                {...register('email')}
                type="email"
                label="Email address"
                placeholder="Enter your email"
                error={errors.email?.message}
                autoComplete="email"
                autoFocus
              />

              <Input
                {...register('password')}
                type={showPassword ? 'text' : 'password'}
                label="Password"
                placeholder="Enter your password"
                error={errors.password?.message}
                autoComplete="current-password"
                rightIcon={
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="text-secondary-400 hover:text-secondary-600 transition-colors"
                  >
                    {showPassword ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </button>
                }
              />

              <div className="flex items-center justify-between">
                <Checkbox
                  {...register('remember_me')}
                  label="Remember me"
                />

                <Link
                  to={ROUTES.FORGOT_PASSWORD}
                  className="text-sm text-primary-600 hover:text-primary-500 transition-colors"
                >
                  Forgot password?
                </Link>
              </div>

              <Button
                type="submit"
                fullWidth
                loading={isLoginLoading}
                disabled={isLoginLoading}
              >
                Sign in
              </Button>
            </form>

            <div className="mt-6">
              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-secondary-200" />
                </div>
                <div className="relative flex justify-center text-sm">
                  <span className="px-2 bg-white text-secondary-500">
                    Or continue with
                  </span>
                </div>
              </div>

              <div className="mt-6 space-y-3">
                <Button
                  variant="outline"
                  fullWidth
                  onClick={toggleSSOModal}
                  leftIcon={<Building className="h-4 w-4" />}
                >
                  Sign in with SSO
                </Button>

                <div className="text-center">
                  <span className="text-sm text-secondary-500">
                    Don't have an account?{' '}
                  </span>
                  <Link
                    to={ROUTES.REGISTER}
                    className="text-sm text-primary-600 hover:text-primary-500 font-medium transition-colors"
                  >
                    Sign up
                  </Link>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Footer */}
        <div className="text-center">
          <p className="text-xs text-secondary-500">
            By signing in, you agree to our{' '}
            <Link
              to={ROUTES.TERMS}
              className="text-primary-600 hover:text-primary-500"
            >
              Terms of Service
            </Link>{' '}
            and{' '}
            <Link
              to={ROUTES.PRIVACY}
              className="text-primary-600 hover:text-primary-500"
            >
              Privacy Policy
            </Link>
          </p>
        </div>
      </div>

      {/* SSO Login Modal */}
      <SSOLogin isOpen={showSSOModal} onClose={toggleSSOModal} />

      {/* MFA Login Prompt */}
      <MFALoginPrompt 
        isOpen={showMFAPrompt} 
        onClose={handleMFACancel}
        onSuccess={handleMFASuccess}
      />
    </div>
  )
}