import React, { useState, useEffect } from 'react'
import { useSearchParams, Navigate, Link } from 'react-router-dom'
import { Eye, EyeOff, Calendar, Check, X, UserPlus, Mail } from 'lucide-react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Card, CardContent } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { useAuth } from '@/hooks/useAuth'
import { ROUTES } from '@/constants/routes'
import { invitationResponseSchema, type InvitationResponseFormData } from '@/types/forms'

export default function InvitationResponse() {
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token')
  const [showPassword, setShowPassword] = useState(false)
  const [showPasswordConfirm, setShowPasswordConfirm] = useState(false)
  const [invitationData, setInvitationData] = useState<any>(null)
  const [userExists, setUserExists] = useState<boolean | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [responseStatus, setResponseStatus] = useState<'idle' | 'success' | 'error'>('idle')
  
  const { respondToInvitation, isInvitationActionLoading } = useAuth()

  const {
    register,
    handleSubmit,
    watch,
    formState: { errors },
  } = useForm<InvitationResponseFormData>({
    resolver: zodResolver(invitationResponseSchema),
    defaultValues: {
      token: token || '',
      action: 'accept',
    },
  })

  const password = watch('password')

  // Check invitation validity and user existence on component mount
  useEffect(() => {
    const checkInvitation = async () => {
      if (!token) {
        setIsLoading(false)
        return
      }

      try {
        // Check invitation details and user existence
        // Since there's no specific endpoint for this, we'll use the respond endpoint
        // with a dry-run approach or create a check endpoint
        const response = await fetch(`/api/v1/users/invitations/check/?token=${token}`)
        
        if (response.ok) {
          const data = await response.json()
          setInvitationData(data.invitation)
          setUserExists(data.user_exists)
        } else {
          setInvitationData(null)
        }
      } catch (error) {
        console.error('Failed to check invitation:', error)
        setInvitationData(null)
      } finally {
        setIsLoading(false)
      }
    }

    checkInvitation()
  }, [token])

  if (!token) {
    return <Navigate to={ROUTES.LOGIN} replace />
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

  const onAccept = (data: InvitationResponseFormData) => {
    respondToInvitation(data)
      .then(() => {
        setResponseStatus('success')
      })
      .catch(() => {
        setResponseStatus('error')
      })
  }

  const onDecline = () => {
    respondToInvitation({
      token: token!,
      action: 'decline',
    })
      .then(() => {
        setResponseStatus('success')
      })
      .catch(() => {
        setResponseStatus('error')
      })
  }

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary-50 to-secondary-100">
        <div className="text-center">
          <LoadingSpinner size="lg" />
          <p className="mt-4 text-secondary-600">Loading invitation...</p>
        </div>
      </div>
    )
  }

  if (!invitationData) {
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
              Invalid Invitation
            </h2>
            <p className="mt-2 text-sm text-secondary-600">
              This invitation link is invalid or has expired.
            </p>
          </div>

          <Card>
            <CardContent className="p-6 text-center">
              <Link to={ROUTES.LOGIN}>
                <Button fullWidth>
                  Go to Sign In
                </Button>
              </Link>
            </CardContent>
          </Card>
        </div>
      </div>
    )
  }

  if (responseStatus === 'success') {
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
              {watch('action') === 'accept' ? 'Welcome to the team!' : 'Invitation declined'}
            </h2>
            <p className="mt-2 text-sm text-secondary-600">
              {watch('action') === 'accept' 
                ? 'Your invitation has been accepted successfully.'
                : 'The invitation has been declined.'
              }
            </p>
          </div>

          <Card>
            <CardContent className="p-6 text-center">
              <Link to={ROUTES.DASHBOARD}>
                <Button fullWidth>
                  {watch('action') === 'accept' ? 'Go to Dashboard' : 'Continue'}
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
            Team Invitation
          </h2>
          <p className="mt-2 text-sm text-secondary-600">
            You've been invited to join a team
          </p>
        </div>

        {/* Invitation Details */}
        <Card>
          <CardContent className="p-6">
            <div className="text-center mb-6">
              <div className="flex justify-center mb-4">
                <div className="p-3 bg-primary-100 rounded-full">
                  <UserPlus className="h-8 w-8 text-primary-600" />
                </div>
              </div>
              
              <h3 className="text-lg font-semibold text-secondary-900 mb-2">
                {invitationData.invited_by_name} has invited you
              </h3>
              
              <div className="space-y-2">
                <div className="flex items-center justify-center space-x-2">
                  <Mail className="h-4 w-4 text-secondary-400" />
                  <span className="text-sm text-secondary-600">{invitationData.invited_email}</span>
                </div>
                
                <div className="flex items-center justify-center space-x-2">
                  <Badge variant="primary" size="sm">
                    {invitationData.role_name}
                  </Badge>
                </div>
              </div>

              {invitationData.message && (
                <div className="mt-4 p-3 bg-secondary-50 rounded-lg">
                  <p className="text-sm text-secondary-700 italic">
                    "{invitationData.message}"
                  </p>
                </div>
              )}
            </div>

            {/* Accept Form */}
            <form onSubmit={handleSubmit(onAccept)} className="space-y-6">
              <input
                {...register('token')}
                type="hidden"
              />
              
              <input
                {...register('action')}
                type="hidden"
                value="accept"
              />

              {/* Show registration fields only if user doesn't exist */}
              {userExists === false && (
                <>
                  <div className="bg-info-50 border border-info-200 rounded-lg p-4 mb-6">
                    <h4 className="font-medium text-info-800 mb-2">Create Your Account</h4>
                    <p className="text-sm text-info-700">
                      We'll create a new account for you with the email {invitationData.invited_email}
                    </p>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <Input
                      {...register('first_name')}
                      label="First Name"
                      placeholder="John"
                      error={errors.first_name?.message}
                      autoComplete="given-name"
                      autoFocus
                      required
                    />
                    <Input
                      {...register('last_name')}
                      label="Last Name"
                      placeholder="Doe"
                      error={errors.last_name?.message}
                      autoComplete="family-name"
                      required
                    />
                  </div>

                  <div className="space-y-2">
                    <Input
                      {...register('password')}
                      type={showPassword ? 'text' : 'password'}
                      label="Password"
                      placeholder="Create a strong password"
                      error={errors.password?.message}
                      autoComplete="new-password"
                      required
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
                    label="Confirm Password"
                    placeholder="Confirm your password"
                    error={errors.password_confirm?.message}
                    autoComplete="new-password"
                    required
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
                </>
              )}

              {/* Show simple confirmation if user exists */}
              {userExists === true && (
                <div className="bg-success-50 border border-success-200 rounded-lg p-4 mb-6">
                  <h4 className="font-medium text-success-800 mb-2">Welcome Back!</h4>
                  <p className="text-sm text-success-700">
                    You already have an account with {invitationData.invited_email}. 
                    Accepting this invitation will add the {invitationData.role_name} role to your existing account.
                  </p>
                </div>
              )}

              <div className="flex space-x-3">
                <Button
                  type="button"
                  variant="outline"
                  onClick={onDecline}
                  disabled={isInvitationActionLoading}
                  className="flex-1"
                >
                  Decline
                </Button>
                <Button
                  type="submit"
                  loading={isInvitationActionLoading}
                  disabled={isInvitationActionLoading}
                  className="flex-1"
                >
                  Accept Invitation
                </Button>
              </div>
            </form>

            <div className="mt-6 text-center">
              <p className="text-xs text-secondary-500">
                By accepting this invitation, you agree to our{' '}
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
          </CardContent>
        </Card>

        {/* Invitation Details */}
        <Card>
          <CardContent className="p-4">
            <h4 className="font-medium text-secondary-900 mb-3">Invitation Details</h4>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-secondary-600">From:</span>
                <span className="text-secondary-900">{invitationData.invited_by_name}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-secondary-600">Role:</span>
                <Badge variant="primary" size="sm">{invitationData.role_name}</Badge>
              </div>
              <div className="flex justify-between">
                <span className="text-secondary-600">Expires:</span>
                <span className="text-secondary-900">
                  {new Date(invitationData.expires_at).toLocaleDateString()}
                </span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}