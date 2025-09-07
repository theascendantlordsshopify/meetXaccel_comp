import React, { useState } from 'react'
import { Link, useSearchParams, Navigate } from 'react-router-dom'
import { Eye, EyeOff, Calendar, Check } from 'lucide-react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Card, CardContent } from '@/components/ui/Card'
import { useAuth } from '@/hooks/useAuth'
import { ROUTES } from '@/constants/routes'
import { passwordResetConfirmSchema, type PasswordResetConfirmFormData } from '@/types/forms'

export default function ResetPassword() {
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token')
  const [showPassword, setShowPassword] = useState(false)
  const [showPasswordConfirm, setShowPasswordConfirm] = useState(false)
  const { confirmPasswordReset, isPasswordResetLoading, clearError } = useAuth()

  const {
    register,
    handleSubmit,
    watch,
    formState: { errors, isSubmitted },
  } = useForm<PasswordResetConfirmFormData>({
    resolver: zodResolver(passwordResetConfirmSchema),
    defaultValues: {
      token: token || '',
    },
  })

  // Clear any previous errors when component mounts
  React.useEffect(() => {
    clearError()
  }, [clearError])

  const password = watch('new_password')

  if (!token) {
    return <Navigate to={ROUTES.FORGOT_PASSWORD} replace />
  }

  const getPasswordStrength = (password: string) => {
    if (!password) return { score: 0, label: '', color: '' }
    
    let score = 0
    if (password.length >= 8) score++
    if (/[A-Z]/.test(password)) score++
    if (/[a-z]/.test(password)) score++
    if (/\d/.test(password)) score++
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score++

    const levels = [
      { score: 0, label: '', color: '' },
      { score: 1, label: 'Very Weak', color: 'bg-error-500' },
      { score: 2, label: 'Weak', color: 'bg-warning-500' },
      { score: 3, label: 'Fair', color: 'bg-warning-400' },
      { score: 4, label: 'Good', color: 'bg-success-400' },
      { score: 5, label: 'Strong', color: 'bg-success-500' },
    ]

    return levels[score] || levels[0]
  }

  const passwordStrength = getPasswordStrength(password || '')

  const onSubmit = (data: PasswordResetConfirmFormData) => {
    confirmPasswordReset(data)
  }

  if (isSubmitted && !isPasswordResetLoading) {
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
              Password reset successful
            </h2>
            <p className="mt-2 text-sm text-secondary-600">
              Your password has been reset successfully. You can now sign in with your new password.
            </p>
          </div>

          <Card>
            <CardContent className="p-6 text-center">
              <Link to={ROUTES.LOGIN}>
                <Button fullWidth>
                  Continue to sign in
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
        {/* Header */}
        <div className="text-center">
          <div className="flex justify-center">
            <Calendar className="h-12 w-12 text-primary-600" />
          </div>
          <h2 className="mt-6 text-3xl font-bold text-secondary-900">
            Set new password
          </h2>
          <p className="mt-2 text-sm text-secondary-600">
            Enter your new password below
          </p>
        </div>

        {/* Reset Form */}
        <Card>
          <CardContent className="p-6">
            <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
              <input
                {...register('token')}
                type="hidden"
              />

              <div className="space-y-2">
                <Input
                  {...register('new_password')}
                  type={showPassword ? 'text' : 'password'}
                  label="New password"
                  placeholder="Enter your new password"
                  error={errors.new_password?.message}
                  autoComplete="new-password"
                  autoFocus
                  rightIcon={
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="text-secondary-400 hover:text-secondary-600"
                    >
                      {showPassword ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </button>
                  }
                />
                
                {/* Password Strength Indicator */}
                {password && (
                  <div className="space-y-2">
                    <div className="flex items-center space-x-2">
                      <div className="flex-1 bg-secondary-200 rounded-full h-2">
                        <div
                          className={`h-2 rounded-full transition-all duration-300 ${passwordStrength.color}`}
                          style={{ width: `${(passwordStrength.score / 5) * 100}%` }}
                        />
                      </div>
                      <span className="text-xs text-secondary-600">
                        {passwordStrength.label}
                      </span>
                    </div>
                  </div>
                )}
              </div>

              <Input
                {...register('new_password_confirm')}
                type={showPasswordConfirm ? 'text' : 'password'}
                label="Confirm new password"
                placeholder="Confirm your new password"
                error={errors.new_password_confirm?.message}
                autoComplete="new-password"
                rightIcon={
                  <button
                    type="button"
                    onClick={() => setShowPasswordConfirm(!showPasswordConfirm)}
                    className="text-secondary-400 hover:text-secondary-600"
                  >
                    {showPasswordConfirm ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </button>
                }
              />

              <Button
                type="submit"
                fullWidth
                loading={isPasswordResetLoading}
                disabled={isPasswordResetLoading}
              >
                Reset password
              </Button>
            </form>

            <div className="mt-6 text-center">
              <Link
                to={ROUTES.LOGIN}
                className="text-sm text-primary-600 hover:text-primary-500 transition-colors"
              >
                Back to sign in
              </Link>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}