import React, { useState } from 'react'
import { Calendar, RefreshCw, Settings, Trash2, AlertTriangle, CheckCircle, XCircle, Plus } from 'lucide-react'
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

export default function CalendarIntegrations() {
  const {
    calendarIntegrations,
    calendarIntegrationsLoading,
    refreshCalendarSync,
    deleteCalendarIntegration,
    isIntegrationActionLoading,
  } = useIntegrations()

  const [selectedIntegration, setSelectedIntegration] = useState<string | null>(null)
  const [showDeleteDialog, { toggle: toggleDeleteDialog }] = useToggle()
  const [showSettingsModal, { toggle: toggleSettingsModal }] = useToggle()

  const handleRefreshSync = (integrationId: string) => {
    refreshCalendarSync(integrationId)
  }

  const handleDeleteIntegration = (integrationId: string) => {
    setSelectedIntegration(integrationId)
    toggleDeleteDialog()
  }

  const confirmDelete = () => {
    if (selectedIntegration) {
      deleteCalendarIntegration(selectedIntegration)
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

  const columns: TableColumn[] = [
    {
      key: 'provider',
      label: 'Provider',
      render: (_, integration) => (
        <div className="flex items-center space-x-3">
          <Calendar className="h-5 w-5 text-primary-600" />
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
      key: 'sync_enabled',
      label: 'Sync',
      render: (_, integration) => (
        <Badge
          variant={integration.sync_enabled ? 'success' : 'secondary'}
          size="sm"
        >
          {integration.sync_enabled ? 'Enabled' : 'Disabled'}
        </Badge>
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
            onClick={() => handleRefreshSync(integration.id)}
            disabled={isIntegrationActionLoading}
            title="Refresh sync"
          >
            <RefreshCw className="h-4 w-4" />
          </Button>
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

  const selectedIntegrationData = calendarIntegrations?.find(i => i.id === selectedIntegration)

  return (
    <div className="space-y-8">
      <PageHeader
        title="Calendar Integrations"
        subtitle="Manage your calendar connections and sync settings"
        breadcrumbs={[
          { label: 'Integrations', href: '/dashboard/integrations' },
          { label: 'Calendar', current: true },
        ]}
        action={
          <Button leftIcon={<Plus className="h-4 w-4" />}>
            Connect Calendar
          </Button>
        }
      />

      <Container>
        {calendarIntegrationsLoading ? (
          <div className="flex items-center justify-center min-h-[400px]">
            <LoadingSpinner size="lg" />
          </div>
        ) : calendarIntegrations?.length === 0 ? (
          <EmptyState
            icon={<Calendar className="h-12 w-12" />}
            title="No calendar integrations"
            description="Connect your calendar to automatically sync events and prevent double bookings"
            action={{
              label: 'Connect Your First Calendar',
              onClick: () => {
                // TODO: Implement calendar connection
              },
            }}
          />
        ) : (
          <DataTable
            columns={columns}
            data={calendarIntegrations || []}
            loading={calendarIntegrationsLoading}
            emptyMessage="No calendar integrations found"
          />
        )}
      </Container>

      {/* Settings Modal */}
      <Modal
        isOpen={showSettingsModal}
        onClose={toggleSettingsModal}
        title="Calendar Integration Settings"
        size="md"
      >
        {selectedIntegrationData && (
          <div className="space-y-6">
            <div className="flex items-center space-x-3">
              <Calendar className="h-8 w-8 text-primary-600" />
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
                  <span className="font-medium text-secondary-900">Sync</span>
                </div>
                <p className="text-sm text-secondary-600">
                  {selectedIntegrationData.sync_enabled ? 'Enabled' : 'Disabled'}
                </p>
              </div>
            </div>

            <div className="bg-warning-50 border border-warning-200 rounded-lg p-4">
              <h4 className="font-medium text-warning-800 mb-2">Important</h4>
              <p className="text-sm text-warning-700">
                Disconnecting this calendar will stop automatic event syncing and may cause scheduling conflicts.
              </p>
            </div>

            <div className="flex space-x-3">
              <Button variant="outline" onClick={toggleSettingsModal} className="flex-1">
                Close
              </Button>
              <Button
                variant="danger"
                onClick={() => {
                  toggleSettingsModal()
                  handleDeleteIntegration(selectedIntegrationData.id)
                }}
                className="flex-1"
              >
                Disconnect
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
        title="Disconnect Calendar Integration"
        message="Are you sure you want to disconnect this calendar integration? This will stop automatic event syncing and may cause scheduling conflicts."
        confirmText="Disconnect"
        variant="danger"
      />
    </div>
  )
}