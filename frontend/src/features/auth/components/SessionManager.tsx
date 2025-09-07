import React from 'react'
import { Monitor, Smartphone, Tablet, MapPin, Clock, Shield } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { useAuth } from '@/hooks/useAuth'
import { useToggle } from '@/hooks/useToggle'
import { formatRelativeTime } from '@/utils/date'

export function SessionManager() {
  const { sessions, sessionsLoading, revokeSession, revokeAllSessions } = useAuth()
  const [showRevokeAllDialog, { toggle: toggleRevokeAllDialog }] = useToggle()

  const getDeviceIcon = (deviceType: string) => {
    switch (deviceType.toLowerCase()) {
      case 'mobile':
        return <Smartphone className="h-5 w-5" />
      case 'tablet':
        return <Tablet className="h-5 w-5" />
      default:
        return <Monitor className="h-5 w-5" />
    }
  }

  const getDeviceInfo = (userAgent: string) => {
    // Simple user agent parsing - in production, you might use a library
    const isMobile = /Mobile|Android|iPhone|iPad/.test(userAgent)
    const isTablet = /iPad|Tablet/.test(userAgent)
    
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

    return {
      type: isTablet ? 'tablet' : isMobile ? 'mobile' : 'desktop',
      browser,
      os,
    }
  }

  if (sessionsLoading) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center justify-center">
            <LoadingSpinner size="lg" />
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <>
      <Card>
        <CardHeader
          title="Active Sessions"
          subtitle="Manage your active sessions across different devices"
          action={
            sessions && sessions.length > 1 && (
              <Button
                variant="outline"
                size="sm"
                onClick={toggleRevokeAllDialog}
                leftIcon={<Shield className="h-4 w-4" />}
              >
                Revoke All Others
              </Button>
            )
          }
        />
        <CardContent>
          {!sessions || sessions.length === 0 ? (
            <div className="text-center py-8">
              <Shield className="h-12 w-12 text-secondary-400 mx-auto mb-4" />
              <p className="text-secondary-600">No active sessions found</p>
            </div>
          ) : (
            <div className="space-y-4">
              {sessions.map((session) => {
                const deviceInfo = getDeviceInfo(session.user_agent)
                
                return (
                  <div
                    key={session.id}
                    className="flex items-center justify-between p-4 border border-secondary-200 rounded-lg hover:border-secondary-300 transition-colors"
                  >
                    <div className="flex items-center space-x-4">
                      <div className="text-secondary-600">
                        {getDeviceIcon(deviceInfo.type)}
                      </div>
                      
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center space-x-2">
                          <p className="text-sm font-medium text-secondary-900">
                            {deviceInfo.browser} on {deviceInfo.os}
                          </p>
                          {session.is_current && (
                            <Badge variant="success" size="sm">
                              Current
                            </Badge>
                          )}
                          {session.is_expired && (
                            <Badge variant="error" size="sm">
                              Expired
                            </Badge>
                          )}
                        </div>
                        
                        <div className="flex items-center space-x-4 mt-1 text-xs text-secondary-500">
                          <div className="flex items-center space-x-1">
                            <MapPin className="h-3 w-3" />
                            <span>{session.location || 'Unknown location'}</span>
                          </div>
                          <div className="flex items-center space-x-1">
                            <Clock className="h-3 w-3" />
                            <span>Last active {formatRelativeTime(session.last_activity)}</span>
                          </div>
                        </div>
                        
                        <p className="text-xs text-secondary-400 mt-1">
                          IP: {session.ip_address}
                        </p>
                      </div>
                    </div>

                    {!session.is_current && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => revokeSession(session.id)}
                      >
                        Revoke
                      </Button>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </CardContent>
      </Card>

      <ConfirmDialog
        isOpen={showRevokeAllDialog}
        onClose={toggleRevokeAllDialog}
        onConfirm={() => {
          revokeAllSessions()
          toggleRevokeAllDialog()
        }}
        title="Revoke All Other Sessions"
        message="This will sign you out of all other devices and browsers. You'll need to sign in again on those devices."
        confirmText="Revoke All"
        variant="warning"
      />
    </>
  )
}