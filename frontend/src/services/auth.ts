import { apiClient } from './api'
import type {
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  RegisterResponse,
  ChangePasswordRequest,
  PasswordResetRequest,
  PasswordResetConfirmRequest,
  EmailVerificationRequest,
  User,
  Profile,
  UserSession,
  AuditLog,
  MFADevice,
  Invitation,
} from '@/types'

export const authService = {
  // Authentication
  login: (data: LoginRequest): Promise<LoginResponse> =>
    apiClient.post('/users/login/', data),

  register: (data: RegisterRequest): Promise<RegisterResponse> =>
    apiClient.post('/users/register/', data),

  logout: (): Promise<{ message: string }> =>
    apiClient.post('/users/logout/'),

  // Password Management
  changePassword: (data: ChangePasswordRequest): Promise<{ message: string; token: string }> =>
    apiClient.post('/users/change-password/', data),

  forcePasswordChange: (data: Omit<ChangePasswordRequest, 'old_password'>): Promise<{ message: string; token: string }> =>
    apiClient.post('/users/force-password-change/', data),

  requestPasswordReset: (data: PasswordResetRequest): Promise<{ message: string }> =>
    apiClient.post('/users/request-password-reset/', data),

  confirmPasswordReset: (data: PasswordResetConfirmRequest): Promise<{ message: string }> =>
    apiClient.post('/users/confirm-password-reset/', data),

  // Email Verification
  verifyEmail: (data: EmailVerificationRequest): Promise<{ message: string }> =>
    apiClient.post('/users/verify-email/', data),

  resendVerification: (email: string): Promise<{ message: string }> =>
    apiClient.post('/users/resend-verification/', { email }),

  // Profile Management
  getProfile: (): Promise<Profile> =>
    apiClient.get('/users/profile/'),

  updateProfile: (data: Partial<Profile>): Promise<Profile> =>
    apiClient.patch('/users/profile/', data),

  getPublicProfile: (organizerSlug: string): Promise<Profile> =>
    apiClient.get(`/users/public/${organizerSlug}/`),

  // Session Management
  getSessions: (): Promise<UserSession[]> =>
    apiClient.get('/users/sessions/'),

  revokeSession: (sessionId: string): Promise<{ message: string }> =>
    apiClient.post(`/users/sessions/${sessionId}/revoke/`),

  revokeAllSessions: (): Promise<{ message: string }> =>
    apiClient.post('/users/sessions/revoke-all/'),

  // Audit Logs
  getAuditLogs: (): Promise<AuditLog[]> =>
    apiClient.get('/users/audit-logs/'),

  // MFA Management
  getMFADevices: (): Promise<MFADevice[]> =>
    apiClient.get('/users/mfa/devices/'),

  setupMFA: (data: { device_type: string; device_name: string; phone_number?: string }): Promise<{
    secret?: string
    qr_code?: string
    manual_entry_key?: string
    message: string
    phone_number?: string
  }> =>
    apiClient.post('/users/mfa/setup/', data),

  verifyMFASetup: (data: { otp_code: string }): Promise<{
    message: string
    backup_codes: string[]
  }> =>
    apiClient.post('/users/mfa/verify/', data),

  disableMFA: (password: string): Promise<{ message: string }> =>
    apiClient.post('/users/mfa/disable/', { password }),

  regenerateBackupCodes: (password: string): Promise<{
    message: string
    backup_codes: string[]
  }> =>
    apiClient.post('/users/mfa/backup-codes/regenerate/', { password }),

  resendSMSOTP: (): Promise<{ message: string }> =>
    apiClient.post('/users/mfa/resend-sms/'),

  sendSMSMFACode: (deviceId: string): Promise<{ message: string }> =>
    apiClient.post('/users/mfa/send-sms-code/', { device_id: deviceId }),

  verifySMSMFA: (data: { otp_code: string; device_id?: string }): Promise<{ message: string }> =>
    apiClient.post('/users/mfa/verify-sms/', data),

  // MFA Login (during authentication flow)
  sendSMSMFACode: (deviceId: string): Promise<{ message: string }> =>
    apiClient.post('/users/mfa/send-sms-code/', { device_id: deviceId }),

  verifyMFALogin: (data: { otp_code: string; device_id?: string }): Promise<{ message: string; token: string }> =>
    apiClient.post('/users/mfa/verify/', data),

  verifyBackupCode: (data: { backup_code: string }): Promise<{ message: string; token: string }> =>
    apiClient.post('/users/mfa/verify-backup/', data),

  // Team Management
  getInvitations: (): Promise<Invitation[]> =>
    apiClient.get('/users/invitations/'),

  createInvitation: (data: {
    invited_email: string
    role: string
    message?: string
  }): Promise<Invitation> =>
    apiClient.post('/users/invitations/', data),

  respondToInvitation: (data: {
    token: string
    action: 'accept' | 'decline'
    first_name?: string
    last_name?: string
    password?: string
    password_confirm?: string
  }): Promise<{
    message: string
    user?: User
    token?: string
  }> =>
    apiClient.post('/users/invitations/respond/', data),

  // Check invitation details and user existence
  checkInvitation: (token: string): Promise<{
    invitation: {
      id: string
      invited_email: string
      role_name: string
      invited_by_name: string
      message?: string
      expires_at: string
    }
    user_exists: boolean
  }> =>
    apiClient.get(`/users/invitations/check/?token=${token}`),

  // Roles & Permissions
  getPermissions: (): Promise<any[]> =>
    apiClient.get('/users/permissions/'),

  getRoles: (): Promise<any[]> =>
    apiClient.get('/users/roles/'),

  // SSO Management
  getSAMLConfigurations: (): Promise<any[]> =>
    apiClient.get('/users/sso/saml/'),

  createSAMLConfiguration: (data: any): Promise<any> =>
    apiClient.post('/users/sso/saml/', data),

  updateSAMLConfiguration: (id: string, data: any): Promise<any> =>
    apiClient.patch(`/users/sso/saml/${id}/`, data),

  deleteSAMLConfiguration: (id: string): Promise<void> =>
    apiClient.delete(`/users/sso/saml/${id}/`),

  getOIDCConfigurations: (): Promise<any[]> =>
    apiClient.get('/users/sso/oidc/'),

  createOIDCConfiguration: (data: any): Promise<any> =>
    apiClient.post('/users/sso/oidc/', data),

  updateOIDCConfiguration: (id: string, data: any): Promise<any> =>
    apiClient.patch(`/users/sso/oidc/${id}/`, data),

  deleteOIDCConfiguration: (id: string): Promise<void> =>
    apiClient.delete(`/users/sso/oidc/${id}/`),

  initiatSSO: (data: {
    sso_type: 'saml' | 'oidc'
    organization_domain: string
    redirect_url?: string
  }): Promise<{
    auth_url: string
    sso_type: string
    organization: string
  }> =>
    apiClient.post('/users/sso/initiate/', data),

  ssoLogout: (): Promise<{
    message: string
    logout_urls: Array<{
      type: string
      url: string
      provider: string
    }>
  }> =>
    apiClient.post('/users/sso/logout/'),

  ssoDiscovery: (domain: string): Promise<{
    domain: string
    providers: Array<{
      type: string
      organization: string
      domain: string
    }>
  }> =>
    apiClient.get(`/users/sso/discovery/?domain=${domain}`),

  getSSOSessions: (): Promise<any[]> =>
    apiClient.get('/users/sso/sessions/'),

  revokeSSOSession: (sessionId: string): Promise<{ message: string }> =>
    apiClient.post(`/users/sso/sessions/${sessionId}/revoke/`),

  // SSO Callback handling
  handleSSOCallback: (data: {
    sso_type: 'saml' | 'oidc'
    code?: string
    state?: string
    saml_response?: string
    relay_state?: string
  }): Promise<{
    user: User
    token: string
    message: string
  }> =>
    apiClient.post('/users/sso/callback/', data),
}

// Helper functions for auth service
export const setAuthToken = (token: string) => {
  api.defaults.headers.common['Authorization'] = `Token ${token}`
}

export const removeAuthToken = () => {
  delete api.defaults.headers.common['Authorization']
}

export const isTokenExpired = (token: string): boolean => {
  try {
    // For Django Token auth, tokens don't have expiration info encoded
    // We rely on the server to return 401 when token is invalid
    return false
  } catch {
    return true
  }
}

export const refreshToken = async (): Promise<string | null> => {
  // Django Token auth doesn't have refresh tokens
  // If token is invalid, user needs to login again
  return null
}

export default authService