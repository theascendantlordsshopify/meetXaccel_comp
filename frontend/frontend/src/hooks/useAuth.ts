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
      authStore.getState().setUser(response.user, response.token)
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
  isLoading: isLoading || loginMutation.isPending || registerMutation.isPending,
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
  changePassword: changePasswordMutation.mutate,
  requestPasswordReset: passwordResetRequestMutation.mutate,
  confirmPasswordReset: passwordResetConfirmMutation.mutate,
  verifyEmail: emailVerificationMutation.mutate,
  resendVerification: resendVerificationMutation.mutate,
  updateProfile: updateProfileMutation.mutate,
  refreshUser,
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
  setupMFA: setupMFAMutation.mutate,
  verifyMFASetup: verifyMFASetupMutation.mutate,
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