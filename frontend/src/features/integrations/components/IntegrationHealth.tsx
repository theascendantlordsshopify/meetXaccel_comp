import React from 'react'
import { Shield, CheckCircle, AlertTriangle, XCircle, RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { useIntegrations } from '@/hooks/useIntegrations'
import { formatRelativeTime } from '@/utils/date'
import { formatProviderName } from '@/utils/format'

export function IntegrationHealth() {
  const { integrationHealth, healthLoading, refreshHealth } = useIntegrations()

  const getHealthIcon = (health: string) => {
    switch (health) {
      case 'healthy':
        return <CheckCircle className="h-5 w-5 text-success-500" />
      case 'degraded':
        return <AlertTriangle className="h-5 w-5 text-warning-500" />
      case 'unhealthy':
        return <XCircle className="h-5 w-5 text-error-500" />
      default:
        return <Shield className="h-5 w-5 text-secondary-400" />
    }
  }

  const getHealthColor = (health: string) => {
    switch (health) {
      case 'healthy':
        return 'success'
      case 'degraded':
        return 'warning'
      case 'unhealthy':
        return 'error'
      default:
        return 'secondary'
    }
  }

  if (healthLoading) {
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

  if (!integrationHealth) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="text-center">
            <Shield className="h-12 w-12 text-secondary-400 mx-auto mb-4" />
            <p className="text-secondary-600">No health data available</p>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader
        title="Integration Health"
        subtitle="Monitor the status of your connected services"
        action={
          <Button
            variant="outline"
            size="sm"
            onClick={refreshHealth}
            leftIcon={<RefreshCw className="h-4 w-4" />}
          >
            Refresh
          </Button>
        }
      />
      <CardContent>
        {/* Overall Health */}
        <div className="flex items-center justify-between mb-6 p-4 bg-secondary-50 rounded-lg">
          <div className="flex items-center space-x-3">
            {getHealthIcon(integrationHealth.overall_health)}
            <div>
              <p className="text-lg font-semibold text-secondary-900 capitalize">
                Overall Health: {integrationHealth.overall_health}
              </p>
              <p className="text-sm text-secondary-600">
                Last checked {formatRelativeTime(integrationHealth.timestamp)}
              </p>
            </div>
          </div>
          <Badge variant={getHealthColor(integrationHealth.overall_health)}>
            {integrationHealth.overall_health}
          </Badge>
        </div>

        {/* Calendar Integrations Health */}
        {integrationHealth.calendar_integrations?.length > 0 && (
          <div className="mb-6">
            <h4 className="font-medium text-secondary-900 mb-3">Calendar Integrations</h4>
            <div className="space-y-3">
              {integrationHealth.calendar_integrations.map((integration, index) => (
                <div
                  key={index}
                  className="flex items-center justify-between p-3 border border-secondary-200 rounded-lg"
                >
                  <div className="flex items-center space-x-3">
                    {getHealthIcon(integration.health)}
                    <div>
                      <p className="text-sm font-medium text-secondary-900">
                        {formatProviderName(integration.provider)}
                      </p>
                      <p className="text-xs text-secondary-500">
                        {integration.last_sync 
                          ? `Last sync: ${formatRelativeTime(integration.last_sync)}`
                          : 'Never synced'
                        }
                      </p>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    <Badge
                      variant={integration.is_active ? 'success' : 'secondary'}
                      size="sm"
                    >
                      {integration.is_active ? 'Active' : 'Inactive'}
                    </Badge>
                    
                    {integration.sync_errors > 0 && (
                      <Badge variant="error" size="sm">
                        {integration.sync_errors} errors
                      </Badge>
                    )}
                    
                    {integration.token_expired && (
                      <Badge variant="warning" size="sm">
                        Token Expired
                      </Badge>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Video Integrations Health */}
        {integrationHealth.video_integrations?.length > 0 && (
          <div>
            <h4 className="font-medium text-secondary-900 mb-3">Video Integrations</h4>
            <div className="space-y-3">
              {integrationHealth.video_integrations.map((integration, index) => (
                <div
                  key={index}
                  className="flex items-center justify-between p-3 border border-secondary-200 rounded-lg"
                >
                  <div className="flex items-center space-x-3">
                    {getHealthIcon(integration.health)}
                    <div>
                      <p className="text-sm font-medium text-secondary-900">
                        {formatProviderName(integration.provider)}
                      </p>
                      <p className="text-xs text-secondary-500">
                        {integration.api_calls_today} API calls today
                      </p>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    <Badge
                      variant={integration.is_active ? 'success' : 'secondary'}
                      size="sm"
                    >
                      {integration.is_active ? 'Active' : 'Inactive'}
                    </Badge>
                    
                    {integration.auto_generate_links && (
                      <Badge variant="info" size="sm">
                        Auto-Generate
                      </Badge>
                    )}
                    
                    {integration.token_expired && (
                      <Badge variant="warning" size="sm">
                        Token Expired
                      </Badge>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* No Integrations */}
        {(!integrationHealth.calendar_integrations?.length && !integrationHealth.video_integrations?.length) && (
          <div className="text-center py-8">
            <Shield className="h-12 w-12 text-secondary-400 mx-auto mb-4" />
            <p className="text-secondary-600">No integrations to monitor</p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}