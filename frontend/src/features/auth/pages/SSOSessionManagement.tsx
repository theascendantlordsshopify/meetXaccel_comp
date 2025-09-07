import React from 'react'
import { Shield, Globe, Monitor, Smartphone, Tablet, MapPin, Clock, Trash2, LogOut } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { Container } from '@/components/layout/Container'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { useAuth } from '@/hooks/useAuth'
import { useToggle } from '@/hooks/useToggle'
import { formatRelativeTime } from '@/utils/date'
import { formatProviderName } from '@/utils/format'

export default function SSOSessionManagement() {
  const { 
    ssoSessions, 
    ssoSessionsLoading, 
    revokeSSOSession, 
    ssoLogout, 
    isSSOActionLoading 
  } = useAuth()
  
  const [selectedSession, setSelectedSession] = React.useState<string | null>(null)
  const [showRevokeDialog, { toggle: toggleRevokeDialog }] = useToggle()
  const [showLogoutAllDialog, { toggle: toggleLogoutAllDialog }] = useToggle()

  const getProviderIcon = (ssoType: string) => {
    switch (ssoType.toLowerCase()) {
      case 'saml':
        return <Shield className="h-5 w-5 text-blue-600" />
      case 'oidc':
        return <Globe className="h-5 w-5 text-green-600" />
      case 'oauth':
        return <Shield className="h-5 w-5 text-purple-600" />
      default:
        return <Shield className="h-5 w-5 text-secondary-600" />
    }
  }

  const getDeviceIcon = (userAgent: string) => {
    const isMobile = /Mobile|Android|iPhone|iPad/.test(userAgent)
    const isTablet = /iPad|Tablet/.test(userAgent)
    
    if (isTablet) return <Tablet className="h-5 w-5" />
    if (isMobile) return <Smartphone className="h-5 w-5" />
    return <Monitor className="h-5 w-5" />
  }

  const getDeviceInfo = (userAgent: string) => {
    let browser = 'Unknown'
    if (userAgent.includes('Chrome')) browser = 'Chrome'
    else if (userAgent.includes('Firefox')) browser = 'Firefox'
    else if (userAgent.includes('Safari')) browser = 'Safari'
    else if (userAgent.includes('Edge')) browser = 'Edge'

    let os = 'Unknown'
    if (userAgent.includes('Windows')) os = 'Windows'
    else if (userAgent.includes('Mac')) os = 'macOS'
    else if (userAgent.includes('Linux')) os = 'Linux'
    else if (userAgent.includes('Android')) os = 'Android'
    else if (userAgent.includes('iPhone') || userAgent.includes('iPad')) os = 'iOS'

    return { browser, os }
  }

  const handleRevokeSession = (sessionId: string) => {
    setSelectedSession(sessionId)
    toggleRevokeDialog()
  }

  const confirmRevokeSession = () => {
    if (selectedSession) {
      revokeSSOSession(selectedSession)
      setSelectedSession(null)
      toggleRevokeDialog()
    }
  }

  const confirmLogoutAll = () => {
    ssoLogout()
    toggleLogoutAllDialog()
  }

  if (ssoSessionsLoading) {
    return (
      <div className="space-y-8">
        <PageHeader
          title="SSO Sessions"
          subtitle="Manage your Single Sign-On sessions"
          breadcrumbs={[
            { label: 'Settings', href: '/dashboard/settings' },
            { label: 'Security', href: '/dashboard/security' },
            { label: 'SSO Sessions', current: true },
          ]}
        />
        <Container>
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center justify-center">
                <LoadingSpinner size="lg" />
              </div>
            </CardContent>
          </Card>
        </Container>
      </div>
    )
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title="SSO Sessions"
        subtitle="Manage your Single Sign-On sessions across different providers"
        breadcrumbs={[
          { label: 'Settings', href: '/dashboard/settings' },
          { label: 'Security', href: '/dashboard/security' },
          { label: 'SSO Sessions', current: true },
        ]}
        action={
          ssoSessions && ssoSessions.length > 0 && (
            <Button
              variant="outline"
              size="sm"
              onClick={toggleLogoutAllDialog}
              leftIcon={<LogOut className="h-4 w-4" />}
            >
              Sign Out of All SSO
            </Button>
          )
        }
      />

      <Container>
        <div className="max-w-4xl mx-auto">
          {/* SSO Status Overview */}
          <Card className="mb-8">
            <CardHeader
              title="SSO Status"
              subtitle="Overview of your Single Sign-On authentication"
            />
            <CardContent>
              <div className="flex items-center justify-between p-4 bg-secondary-50 rounded-lg">
                <div className="flex items-center space-x-3">
                  <Shield className="h-8 w-8 text-primary-600" />
                  <div>
                    <p className="text-lg font-semibold text-secondary-900">
                      {ssoSessions && ssoSessions.length > 0 ? 'SSO Active' : 'No SSO Sessions'}
                    </p>
                    <p className="text-sm text-secondary-600">
                      {ssoSessions && ssoSessions.length > 0
                        ? `You have ${ssoSessions.length} active SSO session${ssoSessions.length !== 1 ? 's' : ''}`
                        : 'You are not currently signed in via SSO'
                      }
                    </p>
                  </div>
                </div>
                {ssoSessions && ssoSessions.length > 0 && (
                  <Badge variant="success" size="sm">
                    {ssoSessions.length} Active
                  </Badge>
                )}
              </div>
            </CardContent>
          </Card>

          {/* SSO Sessions List */}
          <Card>
            <CardHeader
              title="Active SSO Sessions"
              subtitle="Sessions authenticated through external identity providers"
            />
            <CardContent>
              {!ssoSessions || ssoSessions.length === 0 ? (
                <EmptyState
                  icon={<Shield className="h-12 w-12" />}
                  title="No SSO sessions"
                  description="You don't have any active Single Sign-On sessions. SSO sessions are created when you sign in through your organization's identity provider."
                />
              ) : (
                <div className="space-y-4">
                  {ssoSessions.map((session) => {
                    const deviceInfo = getDeviceInfo(session.user_agent)
                    
                    return (
                      <div
                        key={session.id}
                        className="flex items-center justify-between p-4 border border-secondary-200 rounded-lg hover:border-secondary-300 transition-colors"
                      >
                        <div className="flex items-center space-x-4">
                          <div className="flex items-center space-x-2">
                            {getProviderIcon(session.sso_type)}
                            {getDeviceIcon(session.user_agent)}
                          </div>
                          
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center space-x-2">
                              <p className="text-sm font-medium text-secondary-900">
                                {session.provider_name}
                              </p>
                              <Badge variant="info" size="sm">
                                {session.sso_type.toUpperCase()}
                              </Badge>
                            </div>
                            
                            <p className="text-sm text-secondary-600">
                              {deviceInfo.browser} on {deviceInfo.os}
                            </p>
                            
                            <div className="flex items-center space-x-4 mt-1 text-xs text-secondary-500">
                              <div className="flex items-center space-x-1">
                                <MapPin className="h-3 w-3" />
                                <span>{session.ip_address}</span>
                              </div>
                              <div className="flex items-center space-x-1">
                                <Clock className="h-3 w-3" />
                                <span>Last active {formatRelativeTime(session.last_activity)}</span>
                              </div>
                            </div>
                            
                            {session.external_session_id && (
                              <p className="text-xs text-secondary-400 mt-1">
                                Session ID: {session.external_session_id}
                              </p>
                            )}
                          </div>
                        </div>

                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleRevokeSession(session.id)}
                          disabled={isSSOActionLoading}
                          leftIcon={<Trash2 className="h-4 w-4" />}
                        >
                          Revoke
                        </Button>
                      </div>
                    )
                  })}
                </div>
              )}
            </CardContent>
          </Card>

          {/* SSO Information */}
          <Card className="mt-8">
            <CardHeader title="About SSO Sessions" />
            <CardContent>
              <div className="bg-info-50 border border-info-200 rounded-lg p-4">
                <h4 className="font-medium text-info-800 mb-2">How SSO Sessions Work</h4>
                <ul className="text-sm text-info-700 space-y-1 list-disc list-inside">
                  <li>SSO sessions are created when you sign in through your organization's identity provider</li>
                  <li>These sessions allow you to access multiple applications without re-entering credentials</li>
                  <li>Revoking an SSO session will sign you out of this application but may not affect other applications</li>
                  <li>For complete logout from all applications, use "Sign Out of All SSO" which initiates Single Logout (SLO)</li>
                  <li>SSO sessions automatically expire based on your organization's security policies</li>
                </ul>
              </div>
            </CardContent>
          </Card>
        </div>
      </Container>

      {/* Revoke Session Confirmation */}
      <ConfirmDialog
        isOpen={showRevokeDialog}
        onClose={toggleRevokeDialog}
        onConfirm={confirmRevokeSession}
        title="Revoke SSO Session"
        message="Are you sure you want to revoke this SSO session? You will be signed out of this application for this provider."
        confirmText="Revoke Session"
        variant="warning"
      />

      {/* Logout All SSO Confirmation */}
      <ConfirmDialog
        isOpen={showLogoutAllDialog}
        onClose={toggleLogoutAllDialog}
        onConfirm={confirmLogoutAll}
        title="Sign Out of All SSO Providers"
        message="This will sign you out of all SSO providers and may open logout pages for each provider. You will need to sign in again to access the application."
        confirmText="Sign Out of All"
        variant="warning"
      />
    </div>
  )
}