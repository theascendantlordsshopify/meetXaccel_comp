import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { Eye, EyeOff, Calendar, Check } from 'lucide-react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Checkbox } from '@/components/ui/Checkbox'
import { Card, CardContent } from '@/components/ui/Card'
import { useAuth } from '@/hooks/useAuth'
import { ROUTES } from '@/constants/routes'
import { registerSchema, type RegisterFormData } from '@/types/forms'

export default function Register() {
  const [showPassword, setShowPassword] = useState(false)
  const [showPasswordConfirm, setShowPasswordConfirm] = useState(false)
  const { register: registerUser, isRegisterLoading } = useAuth()

  const {
    register,
    handleSubmit,
    watch,
    formState: { errors },
  } = useForm<RegisterFormData>({
    resolver: zodResolver(registerSchema),
  })

  const password = watch('password')

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

  const onSubmit = (data: RegisterFormData) => {
    registerUser(data)
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
            Create your account
          </h2>
          <p className="mt-2 text-sm text-secondary-600">
            Start scheduling meetings like a pro
          </p>
        </div>

        {/* Registration Form */}
        <Card>
          <CardContent className="p-6">
            <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <Input
                  {...register('first_name')}
                  label="First name"
                  placeholder="John"
                  error={errors.first_name?.message}
                  autoComplete="given-name"
                  autoFocus
                />
                <Input
                  {...register('last_name')}
                  label="Last name"
                  placeholder="Doe"
                  error={errors.last_name?.message}
                  autoComplete="family-name"
                />
              </div>

              <Input
                {...register('email')}
                type="email"
                label="Email address"
                placeholder="john@example.com"
                error={errors.email?.message}
                autoComplete="email"
              />

              <div className="space-y-2">
                <Input
                  {...register('password')}
                  type={showPassword ? 'text' : 'password'}
                  label="Password"
                  placeholder="Create a strong password"
                  error={errors.password?.message}
                  autoComplete="new-password"
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
                    
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div className={`flex items-center space-x-1 ${password.length >= 8 ? 'text-success-600' : 'text-secondary-400'}`}>
                        <Check className="h-3 w-3" />
                        <span>8+ characters</span>
                      </div>
                      <div className={`flex items-center space-x-1 ${/[A-Z]/.test(password) ? 'text-success-600' : 'text-secondary-400'}`}>
                        <Check className="h-3 w-3" />
                        <span>Uppercase</span>
                      </div>
                      <div className={`flex items-center space-x-1 ${/[a-z]/.test(password) ? 'text-success-600' : 'text-secondary-400'}`}>
                        <Check className="h-3 w-3" />
                        <span>Lowercase</span>
                      </div>
                      <div className={`flex items-center space-x-1 ${/\d/.test(password) ? 'text-success-600' : 'text-secondary-400'}`}>
                        <Check className="h-3 w-3" />
                        <span>Number</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              <Input
                {...register('password_confirm')}
                type={showPasswordConfirm ? 'text' : 'password'}
                label="Confirm password"
                placeholder="Confirm your password"
                error={errors.password_confirm?.message}
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

              <Checkbox
                {...register('terms_accepted')}
                label={
                  <span className="text-sm">
                    I agree to the{' '}
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
                  </span>
                }
                error={errors.terms_accepted?.message}
              />

              <Button
                type="submit"
                fullWidth
                loading={isRegisterLoading}
                disabled={isRegisterLoading}
              >
                Create account
              </Button>
            </form>

            <div className="mt-6">
              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-secondary-200" />
                </div>
                <div className="relative flex justify-center text-sm">
                  <span className="px-2 bg-white text-secondary-500">
                    Already have an account?
                  </span>
                </div>
              </div>

              <div className="mt-6">
                <Link to={ROUTES.LOGIN}>
                  <Button variant="outline" fullWidth>
                    Sign in instead
                  </Button>
                </Link>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}