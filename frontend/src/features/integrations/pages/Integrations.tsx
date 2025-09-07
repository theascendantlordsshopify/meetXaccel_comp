import React, { useState } from 'react'
import { Calendar, Video, Webhook, Plus, Settings, RefreshCw, AlertTriangle, CheckCircle, XCircle } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { Container } from '@/components/layout/Container'
import { Modal } from '@/components/ui/Modal'
import { useIntegrations } from '@/hooks/useIntegrations'
import { useToggle } from '@/hooks/useToggle'
import { formatRelativeTime } from '@/utils/date'
import { formatProviderName } from '@/utils/format'

export default function Integrations() {
  const {
    calendarIntegrations,
    calendarIntegrationsLoading,
    videoIntegrations,
    videoIntegrationsLoading,
    webhookIntegrations,
    webhookIntegrationsLoading,
    integrationHealth,
    healthLoading,
    refreshCalendarSync,
    isIntegrationActionLoading,
  } = useIntegrations()

  const [showConnectModal, { toggle: toggleConnectModal }] = useToggle()
  const [selectedIntegrationType, setSelectedIntegrationType] = useState<'calendar' | 'video' | 'webhook'>('calendar')

  const handleConnectIntegration = (type: 'calendar' | 'video' | 'webhook') => {
    setSelectedIntegrationType(type)
    toggleConnectModal()
  }

  const handleRefreshSync = (integrationId: string) => {
    refreshCalendarSync(integrationId)
  }

  const getHealthIcon = (health: string) => {
    switch (health) {
      case 'healthy':
        return <CheckCircle className="h-5 w-5 text-success-500" />
      case 'degraded':
        return <AlertTriangle className="h-5 w-5 text-warning-500" />
      case 'unhealthy':
        return <XCircle className="h-5 w-5 text-error-500" />
      default:
        return <AlertTriangle className="h-5 w-5 text-secondary-400" />
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

  const isLoading = calendarIntegrationsLoading || videoIntegrationsLoading || webhookIntegrationsLoading

  return (
    <div className="space-y-8">
      <PageHeader
        title="Integrations"
        subtitle="Connect external services to enhance your scheduling workflow"
        action={
          <div className="flex space-x-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => window.location.reload()}
              leftIcon={<RefreshCw className="h-4 w-4" />}
            >
              Refresh
            </Button>
            <Button
              onClick={() => handleConnectIntegration('calendar')}
              leftIcon={<Plus className="h-4 w-4" />}
            >
              Connect Service
            </Button>
          </div>
        }
      />

      <Container>
        {/* Health Overview */}
        {integrationHealth && (
          <Card className="mb-8">
            <CardHeader
              title="Integration Health"
              subtitle="Overall status of your connected services"
            />
            <CardContent>
              <div className="flex items-center space-x-4">
                {getHealthIcon(integrationHealth.overall_health)}
                <div>
                  <p className="text-lg font-semibold text-secondary-900 capitalize">
                    {integrationHealth.overall_health}
                  </p>
                  <p className="text-sm text-secondary-600">
                    Last checked {formatRelativeTime(integrationHealth.timestamp)}
                  </p>
                </div>
                <Badge variant={getHealthColor(integrationHealth.overall_health)} className="ml-auto">
                  {integrationHealth.overall_health}
                </Badge>
              </div>
            </CardContent>
          </Card>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Calendar Integrations */}
          <div>
            <Card>
              <CardHeader
                title="Calendar Integrations"
                subtitle="Sync with your external calendars"
                action={
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleConnectIntegration('calendar')}
                    leftIcon={<Plus className="h-4 w-4" />}
                  >
                    Connect
                  </Button>
                }
              />
              <CardContent>
                {calendarIntegrationsLoading ? (
                  <div className="flex items-center justify-center py-8">
                    <LoadingSpinner size="md" />
                  </div>
                ) : calendarIntegrations?.length === 0 ? (
                  <EmptyState
                    icon={<Calendar className="h-8 w-8" />}
                    title="No calendar integrations"
                    description="Connect your calendar to sync events"
                    action={{
                      label: 'Connect Calendar',
                      onClick: () => handleConnectIntegration('calendar'),
                    }}
                  />
                ) : (
                  <div className="space-y-4">
                    {calendarIntegrations?.map((integration) => (
                      <div
                        key={integration.id}
                        className="flex items-center justify-between p-4 border border-secondary-200 rounded-lg"
                      >
                        <div className="flex items-center space-x-3">
                          <Calendar className="h-5 w-5 text-primary-600" />
                          <div>
                            <p className="text-sm font-medium text-secondary-900">
                              {formatProviderName(integration.provider)}
                            </p>
                            <p className="text-xs text-secondary-500">
                              {integration.provider_email || 'Connected'}
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
                          
                          {integration.is_token_expired && (
                            <Badge variant="error" size="sm">
                              Token Expired
                            </Badge>
                          )}
                          
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleRefreshSync(integration.id)}
                            disabled={isIntegrationActionLoading}
                          >
                            <RefreshCw className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Video Integrations */}
          <div>
            <Card>
              <CardHeader
                title="Video Integrations"
                subtitle="Auto-generate meeting links"
                action={
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleConnectIntegration('video')}
                    leftIcon={<Plus className="h-4 w-4" />}
                  >
                    Connect
                  </Button>
                }
              />
              <CardContent>
                {videoIntegrationsLoading ? (
                  <div className="flex items-center justify-center py-8">
                    <LoadingSpinner size="md" />
                  </div>
                ) : videoIntegrations?.length === 0 ? (
                  <EmptyState
                    icon={<Video className="h-8 w-8" />}
                    title="No video integrations"
                    description="Connect video services for automatic meeting links"
                    action={{
                      label: 'Connect Video Service',
                      onClick: () => handleConnectIntegration('video'),
                    }}
                  />
                ) : (
                  <div className="space-y-4">
                    {videoIntegrations?.map((integration) => (
                      <div
                        key={integration.id}
                        className="flex items-center justify-between p-4 border border-secondary-200 rounded-lg"
                      >
                        <div className="flex items-center space-x-3">
                          <Video className="h-5 w-5 text-primary-600" />
                          <div>
                            <p className="text-sm font-medium text-secondary-900">
                              {formatProviderName(integration.provider)}
                            </p>
                            <p className="text-xs text-secondary-500">
                              {integration.provider_email || 'Connected'}
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
                              Auto-generate
                            </Badge>
                          )}
                          
                          {integration.is_token_expired && (
                            <Badge variant="error" size="sm">
                              Token Expired
                            </Badge>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Webhook Integrations */}
          <div>
            <Card>
              <CardHeader
                title="Webhook Integrations"
                subtitle="Send data to external services"
                action={
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleConnectIntegration('webhook')}
                    leftIcon={<Plus className="h-4 w-4" />}
                  >
                    Add
                  </Button>
                }
              />
              <CardContent>
                {webhookIntegrationsLoading ? (
                  <div className="flex items-center justify-center py-8">
                    <LoadingSpinner size="md" />
                  </div>
                ) : webhookIntegrations?.length === 0 ? (
                  <EmptyState
                    icon={<Webhook className="h-8 w-8" />}
                    title="No webhook integrations"
                    description="Add webhooks to send data to external services"
                    action={{
                      label: 'Add Webhook',
                      onClick: () => handleConnectIntegration('webhook'),
                    }}
                  />
                ) : (
                  <div className="space-y-4">
                    {webhookIntegrations?.map((integration) => (
                      <div
                        key={integration.id}
                        className="flex items-center justify-between p-4 border border-secondary-200 rounded-lg"
                      >
                        <div className="flex items-center space-x-3">
                          <Webhook className="h-5 w-5 text-primary-600" />
                          <div>
                            <p className="text-sm font-medium text-secondary-900">
                              {integration.name}
                            </p>
                            <p className="text-xs text-secondary-500 truncate max-w-32">
                              {integration.webhook_url}
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
                          
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              // TODO: Open webhook settings
                            }}
                          >
                            <Settings className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Integration Logs */}
        {integrationHealth && (
          <Card className="mt-8">
            <CardHeader title="Recent Activity" />
            <CardContent>
              <div className="space-y-4">
                {integrationHealth.calendar_integrations?.map((cal, index) => (
                  <div key={index} className="flex items-center justify-between p-3 bg-secondary-50 rounded-lg">
                    <div className="flex items-center space-x-3">
                      <Calendar className="h-4 w-4 text-secondary-600" />
                      <div>
                        <p className="text-sm font-medium text-secondary-900">
                          {formatProviderName(cal.provider)} Calendar
                        </p>
                        <p className="text-xs text-secondary-500">
                          {cal.last_sync ? `Last sync: ${formatRelativeTime(cal.last_sync)}` : 'Never synced'}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      {getHealthIcon(cal.health)}
                      <span className="text-xs text-secondary-600">
                        {cal.sync_errors} errors
                      </span>
                    </div>
                  </div>
                ))}
                
                {integrationHealth.video_integrations?.map((video, index) => (
                  <div key={index} className="flex items-center justify-between p-3 bg-secondary-50 rounded-lg">
                    <div className="flex items-center space-x-3">
                      <Video className="h-4 w-4 text-secondary-600" />
                      <div>
                        <p className="text-sm font-medium text-secondary-900">
                          {formatProviderName(video.provider)} Video
                        </p>
                        <p className="text-xs text-secondary-500">
                          {video.api_calls_today} API calls today
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-2">
                      {getHealthIcon(video.health)}
                      <Badge
                        variant={video.auto_generate_links ? 'success' : 'secondary'}
                        size="sm"
                      >
                        {video.auto_generate_links ? 'Auto' : 'Manual'}
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </Container>

      {/* Connect Integration Modal */}
      <Modal
        isOpen={showConnectModal}
        onClose={toggleConnectModal}
        title="Connect Integration"
        size="md"
      >
        <div className="space-y-6">
          <p className="text-secondary-600">
            Choose a service to connect to your Calendly Clone account.
          </p>
          
          {selectedIntegrationType === 'calendar' && (
            <div className="space-y-3">
              <h4 className="font-medium text-secondary-900">Calendar Services</h4>
              <div className="grid grid-cols-1 gap-3">
                <button className="p-4 border-2 border-secondary-200 rounded-lg hover:border-primary-300 hover:bg-primary-50 transition-colors text-left">
                  <div className="flex items-center space-x-3">
                    <div className="w-8 h-8 bg-blue-500 rounded flex items-center justify-center">
                      <span className="text-white text-xs font-bold">G</span>
                    </div>
                    <div>
                      <div className="font-medium text-secondary-900">Google Calendar</div>
                      <div className="text-sm text-secondary-600">Sync with Google Calendar</div>
                    </div>
                  </div>
                </button>
                
                <button className="p-4 border-2 border-secondary-200 rounded-lg hover:border-primary-300 hover:bg-primary-50 transition-colors text-left">
                  <div className="flex items-center space-x-3">
                    <div className="w-8 h-8 bg-blue-600 rounded flex items-center justify-center">
                      <span className="text-white text-xs font-bold">M</span>
                    </div>
                    <div>
                      <div className="font-medium text-secondary-900">Microsoft Outlook</div>
                      <div className="text-sm text-secondary-600">Sync with Outlook Calendar</div>
                    </div>
                  </div>
                </button>
              </div>
            </div>
          )}

          {selectedIntegrationType === 'video' && (
            <div className="space-y-3">
              <h4 className="font-medium text-secondary-900">Video Services</h4>
              <div className="grid grid-cols-1 gap-3">
                <button className="p-4 border-2 border-secondary-200 rounded-lg hover:border-primary-300 hover:bg-primary-50 transition-colors text-left">
                  <div className="flex items-center space-x-3">
                    <div className="w-8 h-8 bg-blue-500 rounded flex items-center justify-center">
                      <span className="text-white text-xs font-bold">Z</span>
                    </div>
                    <div>
                      <div className="font-medium text-secondary-900">Zoom</div>
                      <div className="text-sm text-secondary-600">Auto-generate Zoom meeting links</div>
                    </div>
                  </div>
                </button>
                
                <button className="p-4 border-2 border-secondary-200 rounded-lg hover:border-primary-300 hover:bg-primary-50 transition-colors text-left">
                  <div className="flex items-center space-x-3">
                    <div className="w-8 h-8 bg-green-500 rounded flex items-center justify-center">
                      <span className="text-white text-xs font-bold">G</span>
                    </div>
                    <div>
                      <div className="font-medium text-secondary-900">Google Meet</div>
                      <div className="text-sm text-secondary-600">Auto-generate Google Meet links</div>
                    </div>
                  </div>
                </button>
                
                <button className="p-4 border-2 border-secondary-200 rounded-lg hover:border-primary-300 hover:bg-primary-50 transition-colors text-left">
                  <div className="flex items-center space-x-3">
                    <div className="w-8 h-8 bg-blue-600 rounded flex items-center justify-center">
                      <span className="text-white text-xs font-bold">T</span>
                    </div>
                    <div>
                      <div className="font-medium text-secondary-900">Microsoft Teams</div>
                      <div className="text-sm text-secondary-600">Auto-generate Teams meeting links</div>
                    </div>
                  </div>
                </button>
              </div>
            </div>
          )}

          {selectedIntegrationType === 'webhook' && (
            <div className="space-y-4">
              <h4 className="font-medium text-secondary-900">Add Webhook</h4>
              <p className="text-sm text-secondary-600">
                Webhooks will be sent to your specified URL when events occur.
              </p>
              <Button fullWidth>
                Configure Webhook
              </Button>
            </div>
          )}
        </div>
      </Modal>
    </div>
  )
}