import React, { useState } from 'react'
import { Webhook, Plus, Settings, Trash2, TestTube, Copy, ExternalLink } from 'lucide-react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Textarea } from '@/components/ui/Textarea'
import { Select } from '@/components/ui/Select'
import { Checkbox } from '@/components/ui/Checkbox'
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
import { copyToClipboard } from '@/utils/helpers'
import { webhookIntegrationSchema, type WebhookIntegrationFormData } from '@/types/forms'
import type { TableColumn } from '@/types'

const eventOptions = [
  { value: 'booking_created', label: 'Booking Created' },
  { value: 'booking_cancelled', label: 'Booking Cancelled' },
  { value: 'booking_rescheduled', label: 'Booking Rescheduled' },
  { value: 'booking_completed', label: 'Booking Completed' },
]

export default function WebhookIntegrations() {
  const {
    webhookIntegrations,
    webhookIntegrationsLoading,
    createWebhookIntegration,
    updateWebhookIntegration,
    deleteWebhookIntegration,
    testWebhook,
    isIntegrationActionLoading,
  } = useIntegrations()

  const [selectedIntegration, setSelectedIntegration] = useState<any>(null)
  const [showCreateModal, { toggle: toggleCreateModal }] = useToggle()
  const [showEditModal, { toggle: toggleEditModal }] = useToggle()
  const [showDeleteDialog, { toggle: toggleDeleteDialog }] = useToggle()

  const {
    register,
    handleSubmit,
    watch,
    reset,
    formState: { errors },
  } = useForm<WebhookIntegrationFormData>({
    resolver: zodResolver(webhookIntegrationSchema),
    defaultValues: {
      events: ['booking_created'],
      is_active: true,
      retry_failed: true,
      max_retries: 3,
    },
  })

  const watchedValues = watch()

  const handleCreateWebhook = (data: WebhookIntegrationFormData) => {
    createWebhookIntegration(data)
      .then(() => {
        reset()
        toggleCreateModal()
      })
      .catch(() => {
        // Error handling is done in the hook
      })
  }

  const handleEditWebhook = (integration: any) => {
    setSelectedIntegration(integration)
    reset({
      name: integration.name,
      webhook_url: integration.webhook_url,
      events: integration.events,
      secret_key: '', // Don't pre-fill secret for security
      headers: integration.headers || {},
      is_active: integration.is_active,
      retry_failed: integration.retry_failed,
      max_retries: integration.max_retries,
    })
    toggleEditModal()
  }

  const handleUpdateWebhook = (data: WebhookIntegrationFormData) => {
    if (!selectedIntegration) return

    updateWebhookIntegration({ id: selectedIntegration.id, data })
      .then(() => {
        reset()
        setSelectedIntegration(null)
        toggleEditModal()
      })
      .catch(() => {
        // Error handling is done in the hook
      })
  }

  const handleDeleteWebhook = (integration: any) => {
    setSelectedIntegration(integration)
    toggleDeleteDialog()
  }

  const confirmDelete = () => {
    if (selectedIntegration) {
      deleteWebhookIntegration(selectedIntegration.id)
      setSelectedIntegration(null)
      toggleDeleteDialog()
    }
  }

  const handleTestWebhook = (integrationId: string) => {
    testWebhook(integrationId)
  }

  const handleCopyUrl = async (url: string) => {
    const success = await copyToClipboard(url)
    if (success) {
      // Toast notification will be shown by the copy function
    }
  }

  const columns: TableColumn[] = [
    {
      key: 'name',
      label: 'Name',
      render: (_, integration) => (
        <div className="flex items-center space-x-3">
          <Webhook className="h-5 w-5 text-primary-600" />
          <div>
            <p className="text-sm font-medium text-secondary-900">
              {integration.name}
            </p>
            <p className="text-xs text-secondary-500 truncate max-w-48">
              {integration.webhook_url}
            </p>
          </div>
        </div>
      ),
    },
    {
      key: 'events',
      label: 'Events',
      render: (_, integration) => (
        <div className="flex flex-wrap gap-1">
          {integration.events.slice(0, 2).map((event: string) => (
            <Badge key={event} variant="secondary" size="sm">
              {event.replace('_', ' ')}
            </Badge>
          ))}
          {integration.events.length > 2 && (
            <Badge variant="secondary" size="sm">
              +{integration.events.length - 2} more
            </Badge>
          )}
        </div>
      ),
    },
    {
      key: 'status',
      label: 'Status',
      render: (_, integration) => (
        <Badge
          variant={integration.is_active ? 'success' : 'secondary'}
          size="sm"
        >
          {integration.is_active ? 'Active' : 'Inactive'}
        </Badge>
      ),
    },
    {
      key: 'created_at',
      label: 'Created',
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
            onClick={() => handleTestWebhook(integration.id)}
            disabled={isIntegrationActionLoading}
            title="Test webhook"
          >
            <TestTube className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => handleEditWebhook(integration)}
            title="Edit"
          >
            <Settings className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => handleDeleteWebhook(integration)}
            className="text-error-600 hover:text-error-700"
            title="Delete"
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      ),
    },
  ]

  return (
    <div className="space-y-8">
      <PageHeader
        title="Webhook Integrations"
        subtitle="Send booking data to external services via webhooks"
        breadcrumbs={[
          { label: 'Integrations', href: '/dashboard/integrations' },
          { label: 'Webhooks', current: true },
        ]}
        action={
          <Button
            onClick={toggleCreateModal}
            leftIcon={<Plus className="h-4 w-4" />}
          >
            Add Webhook
          </Button>
        }
      />

      <Container>
        {webhookIntegrationsLoading ? (
          <div className="flex items-center justify-center min-h-[400px]">
            <LoadingSpinner size="lg" />
          </div>
        ) : webhookIntegrations?.length === 0 ? (
          <Card>
            <CardContent className="p-12">
              <EmptyState
                icon={<Webhook className="h-12 w-12" />}
                title="No webhook integrations"
                description="Add webhooks to send booking data to external services like CRM systems, analytics tools, or custom applications"
                action={{
                  label: 'Add Your First Webhook',
                  onClick: toggleCreateModal,
                }}
              />
            </CardContent>
          </Card>
        ) : (
          <Card>
            <CardHeader title="Webhook Endpoints" />
            <CardContent>
              <DataTable
                columns={columns}
                data={webhookIntegrations || []}
                loading={webhookIntegrationsLoading}
                emptyMessage="No webhook integrations found"
              />
            </CardContent>
          </Card>
        )}
      </Container>

      {/* Create Webhook Modal */}
      <Modal
        isOpen={showCreateModal}
        onClose={toggleCreateModal}
        title="Add Webhook Integration"
        size="lg"
      >
        <form onSubmit={handleSubmit(handleCreateWebhook)} className="space-y-6">
          <Input
            {...register('name')}
            label="Webhook Name"
            placeholder="e.g., CRM Integration, Analytics Tracker"
            error={errors.name?.message}
            required
          />

          <Input
            {...register('webhook_url')}
            type="url"
            label="Webhook URL"
            placeholder="https://your-service.com/webhook"
            error={errors.webhook_url?.message}
            required
            rightIcon={
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => window.open('https://webhook.site', '_blank')}
                title="Test with webhook.site"
              >
                <ExternalLink className="h-4 w-4" />
              </Button>
            }
          />

          <div>
            <label className="block text-sm font-medium text-secondary-700 mb-2">
              Events to Send
            </label>
            <div className="space-y-2">
              {eventOptions.map((option) => (
                <Checkbox
                  key={option.value}
                  {...register('events')}
                  value={option.value}
                  label={option.label}
                  checked={watchedValues.events?.includes(option.value)}
                />
              ))}
            </div>
            {errors.events && (
              <p className="text-sm text-error-600 mt-1">{errors.events.message}</p>
            )}
          </div>

          <Input
            {...register('secret_key')}
            label="Secret Key (optional)"
            placeholder="Your webhook secret for signature verification"
            error={errors.secret_key?.message}
            helpText="Used to verify webhook authenticity"
          />

          <Textarea
            {...register('headers')}
            label="Custom Headers (optional)"
            placeholder='{"Authorization": "Bearer token", "X-Custom": "value"}'
            error={errors.headers?.message}
            helpText="JSON object with custom headers to send"
            rows={3}
          />

          <div className="grid grid-cols-2 gap-4">
            <Checkbox
              {...register('is_active')}
              label="Active"
              description="Enable this webhook"
            />

            <Checkbox
              {...register('retry_failed')}
              label="Retry Failed"
              description="Retry failed webhook deliveries"
            />
          </div>

          <Input
            {...register('max_retries', { valueAsNumber: true })}
            type="number"
            label="Max Retries"
            min={0}
            max={10}
            error={errors.max_retries?.message}
            helpText="Maximum number of retry attempts"
          />

          <div className="flex space-x-3">
            <Button type="button" variant="outline" onClick={toggleCreateModal} className="flex-1">
              Cancel
            </Button>
            <Button
              type="submit"
              loading={isIntegrationActionLoading}
              disabled={isIntegrationActionLoading}
              className="flex-1"
            >
              Add Webhook
            </Button>
          </div>
        </form>
      </Modal>

      {/* Edit Webhook Modal */}
      <Modal
        isOpen={showEditModal}
        onClose={toggleEditModal}
        title="Edit Webhook Integration"
        size="lg"
      >
        <form onSubmit={handleSubmit(handleUpdateWebhook)} className="space-y-6">
          <Input
            {...register('name')}
            label="Webhook Name"
            placeholder="e.g., CRM Integration, Analytics Tracker"
            error={errors.name?.message}
            required
          />

          <div className="flex items-center space-x-2">
            <Input
              {...register('webhook_url')}
              type="url"
              label="Webhook URL"
              placeholder="https://your-service.com/webhook"
              error={errors.webhook_url?.message}
              required
              className="flex-1"
            />
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => handleCopyUrl(watchedValues.webhook_url || '')}
              className="mt-6"
            >
              <Copy className="h-4 w-4" />
            </Button>
          </div>

          <div>
            <label className="block text-sm font-medium text-secondary-700 mb-2">
              Events to Send
            </label>
            <div className="space-y-2">
              {eventOptions.map((option) => (
                <Checkbox
                  key={option.value}
                  {...register('events')}
                  value={option.value}
                  label={option.label}
                  checked={watchedValues.events?.includes(option.value)}
                />
              ))}
            </div>
          </div>

          <Input
            {...register('secret_key')}
            label="Secret Key (optional)"
            placeholder="Leave empty to keep existing secret"
            error={errors.secret_key?.message}
            helpText="Used to verify webhook authenticity"
          />

          <Textarea
            {...register('headers')}
            label="Custom Headers (optional)"
            placeholder='{"Authorization": "Bearer token", "X-Custom": "value"}'
            error={errors.headers?.message}
            helpText="JSON object with custom headers to send"
            rows={3}
          />

          <div className="grid grid-cols-2 gap-4">
            <Checkbox
              {...register('is_active')}
              label="Active"
              description="Enable this webhook"
            />

            <Checkbox
              {...register('retry_failed')}
              label="Retry Failed"
              description="Retry failed webhook deliveries"
            />
          </div>

          <Input
            {...register('max_retries', { valueAsNumber: true })}
            type="number"
            label="Max Retries"
            min={0}
            max={10}
            error={errors.max_retries?.message}
            helpText="Maximum number of retry attempts"
          />

          <div className="flex space-x-3">
            <Button type="button" variant="outline" onClick={toggleEditModal} className="flex-1">
              Cancel
            </Button>
            <Button
              type="submit"
              loading={isIntegrationActionLoading}
              disabled={isIntegrationActionLoading}
              className="flex-1"
            >
              Update Webhook
            </Button>
          </div>
        </form>
      </Modal>

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        isOpen={showDeleteDialog}
        onClose={toggleDeleteDialog}
        onConfirm={confirmDelete}
        title="Delete Webhook Integration"
        message="Are you sure you want to delete this webhook integration? This action cannot be undone."
        confirmText="Delete"
        variant="danger"
      />
    </div>
  )
}