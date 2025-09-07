import React, { useState } from 'react'
import { Video, Settings, Trash2, AlertTriangle, CheckCircle, XCircle, Plus, Zap } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { Container } from '@/components/layout/Container'
import { Modal } from '@/components/ui/Modal'
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { DataTable } from '@/components/shared/DataTable'
import { useIntegrations } from '@/hooks/useIntegrations'
import { useToggle } from '@/hooks/useToggle'
import { formatRelativeTime } from '@/utils/date'
import { formatProviderName } from '@/utils/format'
import type { TableColumn } from '@/types'

export default function VideoIntegrations() {
  const {
    videoIntegrations,
    videoIntegrationsLoading,
    deleteVideoIntegration,
    isIntegrationActionLoading,
  } = useIntegrations()

  const [selectedIntegration, setSelectedIntegration] = useState<string | null>(null)
  const [showDeleteDialog, { toggle: toggleDeleteDialog }] = useToggle()
  const [showSettingsModal, { toggle: toggleSettingsModal }] = useToggle()

  const handleDeleteIntegration = (integrationId: string) => {
    setSelectedIntegration(integrationId)
    toggleDeleteDialog()
  }

  const confirmDelete = () => {
    if (selectedIntegration) {
      deleteVideoIntegration(selectedIntegration)
      setSelectedIntegration(null)
      toggleDeleteDialog()
    }
  }

  const handleSettings = (integrationId: string) => {
    setSelectedIntegration(integrationId)
    toggleSettingsModal()
  }

  const getStatusIcon = (integration: any) => {
    if (!integration.is_active) {
      return <XCircle className="h-4 w-4 text-error-500" />
    }
    if (integration.is_token_expired) {
      return <AlertTriangle className="h-4 w-4 text-warning-500" />
    }
    return <CheckCircle className="h-4 w-4 text-success-500" />
  }

  const getProviderIcon = (provider: string) => {
    const iconClass = "w-8 h-8 rounded flex items-center justify-center text-white text-xs font-bold"
    
    switch (provider) {
      case 'zoom':
        return (
          <div className={`${iconClass} bg-blue-500`}>
            <span>Z</span>
          </div>
        )
      case 'google_meet':
        return (
          <div className={`${iconClass} bg-green-500`}>
            <span>G</span>
          </div>
        )
      case 'microsoft_teams':
        return (
          <div className={`${iconClass} bg-blue-600`}>
            <span>T</span>
          </div>
        )
      case 'webex':
        return (
          <div className={`${iconClass} bg-green-600`}>
            <span>W</span>
          </div>
        )
      default:
        return (
          <div className={`${iconClass} bg-secondary-500`}>
            <Video className="h-4 w-4" />
          </div>
        )
    }
  }

  const columns: TableColumn[] = [
    {
      key: 'provider',
      label: 'Provider',
      render: (_, integration) => (
        <div className="flex items-center space-x-3">
          {getProviderIcon(integration.provider)}
          <div>
            <p className="text-sm font-medium text-secondary-900">
              {formatProviderName(integration.provider)}
            </p>
            <p className="text-xs text-secondary-500">
              {integration.provider_email || 'No email available'}
            </p>
          </div>
        </div>
      ),
    },
    {
      key: 'status',
      label: 'Status',
      render: (_, integration) => (
        <div className="flex items-center space-x-2">
          {getStatusIcon(integration)}
          <div>
            <Badge
              variant={integration.is_active ? 'success' : 'secondary'}
              size="sm"
            >
              {integration.is_active ? 'Active' : 'Inactive'}
            </Badge>
            {integration.is_token_expired && (
              <Badge variant="error" size="sm" className="ml-1">
                Token Expired
              </Badge>
            )}
          </div>
        </div>
      ),
    },
    {
      key: 'auto_generate_links',
      label: 'Auto-Generate',
      render: (_, integration) => (
        <div className="flex items-center space-x-2">
          <Badge
            variant={integration.auto_generate_links ? 'success' : 'secondary'}
            size="sm"
          >
            {integration.auto_generate_links ? 'Enabled' : 'Disabled'}
          </Badge>
          {integration.auto_generate_links && (
            <Zap className="h-4 w-4 text-warning-500" title="Automatically generates meeting links" />
          )}
        </div>
      ),
    },
    {
      key: 'created_at',
      label: 'Connected',
      render: (_, integration) => (
        <span className="text-sm text-secondary-600">
          {formatRelativeTime(integration.created_at)}
        </span>
      ),
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (_, integration) => (
        <div className="flex items-center space-x-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => handleSettings(integration.id)}
            title="Settings"
          >
            <Settings className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => handleDeleteIntegration(integration.id)}
            className="text-error-600 hover:text-error-700"
            title="Delete"
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      ),
    },
  ]

  const selectedIntegrationData = videoIntegrations?.find(i => i.id === selectedIntegration)

  return (
    <div className="space-y-8">
      <PageHeader
        title="Video Integrations"
        subtitle="Manage video conferencing connections for automatic meeting link generation"
        breadcrumbs={[
          { label: 'Integrations', href: '/dashboard/integrations' },
          { label: 'Video', current: true },
        ]}
        action={
          <Button leftIcon={<Plus className="h-4 w-4" />}>
            Connect Video Service
          </Button>
        }
      />

      <Container>
        {/* Quick Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <div className="flex-1">
                  <p className="text-sm font-medium text-secondary-600">Total Integrations</p>
                  <p className="text-2xl font-bold text-secondary-900">
                    {videoIntegrations?.length || 0}
                  </p>
                </div>
                <div className="p-3 bg-primary-100 rounded-lg">
                  <Video className="h-6 w-6 text-primary-600" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <div className="flex-1">
                  <p className="text-sm font-medium text-secondary-600">Active</p>
                  <p className="text-2xl font-bold text-secondary-900">
                    {videoIntegrations?.filter(i => i.is_active).length || 0}
                  </p>
                </div>
                <div className="p-3 bg-success-100 rounded-lg">
                  <CheckCircle className="h-6 w-6 text-success-600" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-6">
              <div className="flex items-center">
                <div className="flex-1">
                  <p className="text-sm font-medium text-secondary-600">Auto-Generate</p>
                  <p className="text-2xl font-bold text-secondary-900">
                    {videoIntegrations?.filter(i => i.auto_generate_links).length || 0}
                  </p>
                </div>
                <div className="p-3 bg-warning-100 rounded-lg">
                  <Zap className="h-6 w-6 text-warning-600" />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {videoIntegrationsLoading ? (
          <div className="flex items-center justify-center min-h-[400px]">
            <LoadingSpinner size="lg" />
          </div>
        ) : videoIntegrations?.length === 0 ? (
          <Card>
            <CardContent className="p-12">
              <EmptyState
                icon={<Video className="h-12 w-12" />}
                title="No video integrations"
                description="Connect video conferencing services to automatically generate meeting links for your bookings"
                action={{
                  label: 'Connect Video Service',
                  onClick: () => {
                    // TODO: Implement video service connection
                  },
                }}
              />
            </CardContent>
          </Card>
        ) : (
          <Card>
            <CardHeader title="Connected Video Services" />
            <CardContent>
              <DataTable
                columns={columns}
                data={videoIntegrations || []}
                loading={videoIntegrationsLoading}
                emptyMessage="No video integrations found"
              />
            </CardContent>
          </Card>
        )}
      </Container>

      {/* Settings Modal */}
      <Modal
        isOpen={showSettingsModal}
        onClose={toggleSettingsModal}
        title="Video Integration Settings"
        size="md"
      >
        {selectedIntegrationData && (
          <div className="space-y-6">
            <div className="flex items-center space-x-3">
              {getProviderIcon(selectedIntegrationData.provider)}
              <div>
                <h3 className="text-lg font-semibold text-secondary-900">
                  {formatProviderName(selectedIntegrationData.provider)}
                </h3>
                <p className="text-sm text-secondary-600">
                  {selectedIntegrationData.provider_email}
                </p>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="bg-secondary-50 p-4 rounded-lg">
                <div className="flex items-center space-x-2 mb-2">
                  <span className="font-medium text-secondary-900">Status</span>
                  {getStatusIcon(selectedIntegrationData)}
                </div>
                <p className="text-sm text-secondary-600">
                  {selectedIntegrationData.is_active ? 'Active' : 'Inactive'}
                </p>
              </div>

              <div className="bg-secondary-50 p-4 rounded-lg">
                <div className="flex items-center space-x-2 mb-2">
                  <span className="font-medium text-secondary-900">Auto-Generate</span>
                  <Zap className="h-4 w-4 text-warning-500" />
                </div>
                <p className="text-sm text-secondary-600">
                  {selectedIntegrationData.auto_generate_links ? 'Enabled' : 'Disabled'}
                </p>
              </div>
            </div>

            {selectedIntegrationData.is_token_expired && (
              <div className="bg-error-50 border border-error-200 rounded-lg p-4">
                <h4 className="font-medium text-error-800 mb-2">Token Expired</h4>
                <p className="text-sm text-error-700">
                  Your authentication token has expired. Please reconnect this service to continue generating meeting links.
                </p>
              </div>
            )}

            <div className="bg-info-50 border border-info-200 rounded-lg p-4">
              <h4 className="font-medium text-info-800 mb-2">How it works</h4>
              <p className="text-sm text-info-700">
                When auto-generate is enabled, meeting links will be automatically created for all video call bookings using this service.
              </p>
            </div>

            <div className="flex space-x-3">
              <Button variant="outline" onClick={toggleSettingsModal} className="flex-1">
                Close
              </Button>
              <Button
                variant="primary"
                onClick={() => {
                  // TODO: Implement reconnection
                }}
                className="flex-1"
              >
                {selectedIntegrationData.is_token_expired ? 'Reconnect' : 'Test Connection'}
              </Button>
            </div>
          </div>
        )}
      </Modal>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        isOpen={showDeleteDialog}
        onClose={toggleDeleteDialog}
        onConfirm={confirmDelete}
        title="Disconnect Video Integration"
        message="Are you sure you want to disconnect this video integration? Future bookings will not automatically generate meeting links."
        confirmText="Disconnect"
        variant="danger"
      />
    </div>
  )
}