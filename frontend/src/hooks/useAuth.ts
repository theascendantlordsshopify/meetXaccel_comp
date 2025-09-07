import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { authService } from '@/services/auth'
import { authStore } from '@/stores/authStore'
import { useUI } from '@/stores/uiStore'
import type {
  LoginRequest,
  RegisterRequest,
  ChangePasswordRequest,
  PasswordResetRequest,
  PasswordResetConfirmRequest,
  EmailVerificationRequest,
  User,
  Profile,
  UserSession,
  MFADevice,
  Invitation,
} from '@/types'

export function useAuth() {
  const queryClient = useQueryClient()
  const { showSuccess, showError } = useUI()
  
  // Get auth state from store
  const {
    user,
    token,
    isAuthenticated,
    isLoading: storeLoading,
    error,
    login: storeLogin,
    register: storeRegister,
    logout: storeLogout,
    setUser,
    updateProfile: storeUpdateProfile,
    refreshUser: storeRefreshUser,
    clearError,
    setLoading,
    setError,
  } = authStore()

  // Login mutation
  const loginMutation = useMutation({
    mutationFn: (data: { email: string; password: string; rememberMe?: boolean }) =>
      storeLogin(data.email, data.password, data.rememberMe),
    onSuccess: () => {
      showSuccess('Welcome back!', 'You have been signed in successfully.')
      queryClient.invalidateQueries({ queryKey: ['user'] })
    },
    onError: (error: any) => {
      showError('Sign in failed', error.message || 'Please check your credentials and try again.')
    },
  })

  // Register mutation
  const registerMutation = useMutation({
    mutationFn: (data: RegisterRequest) => storeRegister(data),
    onSuccess: () => {
      showSuccess('Account created!', 'Welcome to Calendly Clone. Your account has been created successfully.')
      queryClient.invalidateQueries({ queryKey: ['user'] })
    },
    onError: (error: any) => {
      showError('Registration failed', error.message || 'Please check your information and try again.')
    },
  })

  // Logout mutation
  const logoutMutation = useMutation({
    mutationFn: () => Promise.resolve(storeLogout()),
    onSuccess: () => {
      showSuccess('Signed out', 'You have been signed out successfully.')
      queryClient.clear()
    },
  })

  // Change password mutation
  const changePasswordMutation = useMutation({
    mutationFn: (data: ChangePasswordRequest) => authService.changePassword(data),
    onSuccess: (response) => {
      showSuccess('Password changed', 'Your password has been updated successfully.')
      // Update token if provided
      if (response.token) {
        setUser(user!, response.token)
      }
    },
    onError: (error: any) => {
      showError('Failed to change password', error.message)
    },
  })

  // Password reset request mutation
  const passwordResetRequestMutation = useMutation({
    mutationFn: (data: PasswordResetRequest) => authService.requestPasswordReset(data),
    onSuccess: () => {
      showSuccess('Reset link sent', 'Please check your email for password reset instructions.')
    },
    onError: (error: any) => {
      showError('Failed to send reset link', error.message)
    },
  })

  // Password reset confirm mutation
  const passwordResetConfirmMutation = useMutation({
    mutationFn: (data: PasswordResetConfirmRequest) => authService.confirmPasswordReset(data),
    onSuccess: () => {
      showSuccess('Password reset successful', 'Your password has been reset. You can now sign in with your new password.')
    },
    onError: (error: any) => {
      showError('Failed to reset password', error.message)
    },
  })

  // Email verification mutation
  const emailVerificationMutation = useMutation({
    mutationFn: (token: string) => authService.verifyEmail({ token }),
    onSuccess: () => {
      showSuccess('Email verified!', 'Your email has been verified successfully.')
      queryClient.invalidateQueries({ queryKey: ['user'] })
      // Refresh user data to update verification status
      storeRefreshUser()
    },
    onError: (error: any) => {
      showError('Email verification failed', error.message)
    },
  })

  // Resend verification mutation
  const resendVerificationMutation = useMutation({
    mutationFn: (email: string) => authService.resendVerification(email),
    onSuccess: () => {
      showSuccess('Verification email sent', 'Please check your email for the verification link.')
    },
    onError: (error: any) => {
      showError('Failed to send verification email', error.message)
    },
  })

  // Update profile mutation
  const updateProfileMutation = useMutation({
    mutationFn: (data: Partial<Profile>) => storeUpdateProfile(data),
    onSuccess: () => {
      showSuccess('Profile updated', 'Your profile has been updated successfully.')
      queryClient.invalidateQueries({ queryKey: ['user'] })
    },
    onError: (error: any) => {
      showError('Failed to update profile', error.message)
    },
  })

  // Sessions query
  const {
    data: sessions,
    isLoading: sessionsLoading,
    error: sessionsError,
  } = useQuery({
    queryKey: ['user', 'sessions'],
    queryFn: () => authService.getSessions(),
    enabled: isAuthenticated,
  })

  // Revoke session mutation
  const revokeSessionMutation = useMutation({
    mutationFn: (sessionId: string) => authService.revokeSession(sessionId),
    onSuccess: () => {
      showSuccess('Session revoked', 'The session has been revoked successfully.')
      queryClient.invalidateQueries({ queryKey: ['user', 'sessions'] })
    },
    onError: (error: any) => {
      showError('Failed to revoke session', error.message)
    },
  })

  // Revoke all sessions mutation
  const revokeAllSessionsMutation = useMutation({
    mutationFn: () => authService.revokeAllSessions(),
    onSuccess: () => {
      showSuccess('All sessions revoked', 'All other sessions have been revoked successfully.')
      queryClient.invalidateQueries({ queryKey: ['user', 'sessions'] })
    },
    onError: (error: any) => {
      showError('Failed to revoke sessions', error.message)
    },
  })

  // MFA devices query
  const {
    data: mfaDevices,
    isLoading: mfaDevicesLoading,
    error: mfaDevicesError,
  } = useQuery({
    queryKey: ['user', 'mfaDevices'],
    queryFn: () => authService.getMFADevices(),
    enabled: isAuthenticated,
  })

  // Setup MFA mutation
  const setupMFAMutation = useMutation({
    mutationFn: (data: { device_type: string; device_name: string; phone_number?: string }) =>
      authService.setupMFA(data),
    onSuccess: () => {
      showSuccess('MFA setup initiated', 'Please complete the verification step.')
    },
    onError: (error: any) => {
      showError('Failed to setup MFA', error.message)
    },
  })

  // Verify MFA setup mutation
  const verifyMFASetupMutation = useMutation({
    mutationFn: (data: { otp_code: string }) => authService.verifyMFASetup(data),
    onSuccess: () => {
      showSuccess('MFA enabled!', 'Multi-factor authentication has been enabled for your account.')
      queryClient.invalidateQueries({ queryKey: ['user'] })
      queryClient.invalidateQueries({ queryKey: ['user', 'mfaDevices'] })
      // Refresh user data to update MFA status
      storeRefreshUser()
    },
    onError: (error: any) => {
      showError('Failed to verify MFA', error.message)
    },
  })

  // Disable MFA mutation
  const disableMFAMutation = useMutation({
    mutationFn: (password: string) => authService.disableMFA(password),
    onSuccess: () => {
      showSuccess('MFA disabled', 'Multi-factor authentication has been disabled.')
      queryClient.invalidateQueries({ queryKey: ['user'] })
      queryClient.invalidateQueries({ queryKey: ['user', 'mfaDevices'] })
      // Refresh user data to update MFA status
      storeRefreshUser()
    },
    onError: (error: any) => {
      showError('Failed to disable MFA', error.message)
    },
  })

  // Invitations query
  const {
    data: invitations,
    isLoading: invitationsLoading,
    error: invitationsError,
  } = useQuery({
    queryKey: ['user', 'invitations'],
    queryFn: () => authService.getInvitations(),
    enabled: isAuthenticated,
  })

  // Create invitation mutation
  const createInvitationMutation = useMutation({
    mutationFn: (data: { invited_email: string; role: string; message?: string }) =>
      authService.createInvitation(data),
    onSuccess: () => {
      showSuccess('Invitation sent', 'The invitation has been sent successfully.')
      queryClient.invalidateQueries({ queryKey: ['user', 'invitations'] })
    },
    onError: (error: any) => {
      showError('Failed to send invitation', error.message)
    },
  })

  // Respond to invitation mutation
  const respondToInvitationMutation = useMutation({
    mutationFn: (data: {
      token: string
      action: 'accept' | 'decline'
      first_name?: string
      last_name?: string
      password?: string
      password_confirm?: string
    }) => authService.respondToInvitation(data),
    onSuccess: (response) => {
      if (response.user && response.token) {
        // Auto-login after accepting invitation
        setUser(response.user, response.token)
        showSuccess('Invitation accepted', 'Welcome to the team!')
      } else {
        showSuccess('Invitation declined', 'The invitation has been declined.')
      }
      queryClient.invalidateQueries({ queryKey: ['user'] })
    },
    onError: (error: any) => {
      showError('Failed to respond to invitation', error.message)
    },
  })

  return {
    // State
    user,
    token,
    isAuthenticated,
    isLoading: storeLoading || loginMutation.isPending || registerMutation.isPending,
    error,
    
    // Computed values
    isOrganizer: user?.is_organizer || false,
    isEmailVerified: user?.is_email_verified || false,
    isMFAEnabled: user?.is_mfa_enabled || false,
    accountStatus: user?.account_status || 'unknown',
    organizerSlug: user?.profile?.organizer_slug || '',
    displayName: user?.profile?.display_name || user?.full_name || '',
    
    // Permission helpers
    hasRole: (roleName: string) => user?.roles?.some(role => role.name === roleName) || false,
    hasPermission: (permission: string) => 
      user?.roles?.some(role => 
        role.role_permissions?.some(perm => perm.codename === permission)
      ) || false,
    
    // Actions
    login: loginMutation.mutate,
    register: registerMutation.mutate,
    logout: logoutMutation.mutate,
    setUser,
    changePassword: changePasswordMutation.mutate,
    requestPasswordReset: passwordResetRequestMutation.mutate,
    confirmPasswordReset: passwordResetConfirmMutation.mutate,
    verifyEmail: emailVerificationMutation.mutate,
    resendVerification: resendVerificationMutation.mutate,
    updateProfile: updateProfileMutation.mutate,
    refreshUser: storeRefreshUser,
    clearError,
    
    // Session management
    sessions,
    sessionsLoading,
    sessionsError,
    revokeSession: revokeSessionMutation.mutate,
    revokeAllSessions: revokeAllSessionsMutation.mutate,
    
    // MFA management
    mfaDevices,
    mfaDevicesLoading,
    mfaDevicesError,
    setupMFA: setupMFAMutation.mutateAsync,
    verifyMFASetup: verifyMFASetupMutation.mutateAsync,
    disableMFA: disableMFAMutation.mutate,
    
    // Team management
    invitations,
    invitationsLoading,
    invitationsError,
    createInvitation: createInvitationMutation.mutate,
    respondToInvitation: respondToInvitationMutation.mutate,
    
    // Loading states
    isLoginLoading: loginMutation.isPending,
    isRegisterLoading: registerMutation.isPending,
    isLogoutLoading: logoutMutation.isPending,
    isChangePasswordLoading: changePasswordMutation.isPending,
    isPasswordResetLoading: passwordResetRequestMutation.isPending || passwordResetConfirmMutation.isPending,
    isEmailVerificationLoading: emailVerificationMutation.isPending || resendVerificationMutation.isPending,
    isProfileUpdateLoading: updateProfileMutation.isPending,
    isSessionActionLoading: revokeSessionMutation.isPending || revokeAllSessionsMutation.isPending,
    isMFAActionLoading: setupMFAMutation.isPending || verifyMFASetupMutation.isPending || disableMFAMutation.isPending,
    isInvitationActionLoading: createInvitationMutation.isPending || respondToInvitationMutation.isPending,
  }
}