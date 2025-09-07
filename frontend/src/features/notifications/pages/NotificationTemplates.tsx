import React, { useState } from 'react'
import { Plus, Mail, MessageSquare, Edit, Trash2, TestTube, Copy, MoreHorizontal } from 'lucide-react'
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
import { useNotifications } from '@/hooks/useNotifications'
import { useToggle } from '@/hooks/useToggle'
import { ROUTES } from '@/constants/routes'
import { formatRelativeTime } from '@/utils/date'
import { formatNotificationType } from '@/utils/format'
import { notificationTemplateSchema, type NotificationTemplateFormData } from '@/types/forms'
import type { NotificationTemplate } from '@/types'

const templateTypeOptions = [
  { value: 'booking_confirmation', label: 'Booking Confirmation' },
  { value: 'booking_reminder', label: 'Booking Reminder' },
  { value: 'booking_cancellation', label: 'Booking Cancellation' },
  { value: 'booking_rescheduled', label: 'Booking Rescheduled' },
  { value: 'follow_up', label: 'Follow-up' },
  { value: 'custom', label: 'Custom' },
]

const notificationTypeOptions = [
  { value: 'email', label: 'Email' },
  { value: 'sms', label: 'SMS' },
]

export default function NotificationTemplates() {
  const [selectedTemplate, setSelectedTemplate] = useState<NotificationTemplate | null>(null)
  const [showCreateModal, { toggle: toggleCreateModal }] = useToggle()
  const [showEditModal, { toggle: toggleEditModal }] = useToggle()
  const [showDeleteDialog, { toggle: toggleDeleteDialog }] = useToggle()
  const [showTestModal, { toggle: toggleTestModal }] = useToggle()

  const {
    notificationTemplates,
    notificationTemplatesLoading,
    createNotificationTemplate,
    updateNotificationTemplate,
    deleteNotificationTemplate,
    testNotificationTemplate,
    isNotificationActionLoading,
  } = useNotifications()

  const {
    register,
    handleSubmit,
    watch,
    reset,
    formState: { errors },
  } = useForm<NotificationTemplateFormData>({
    resolver: zodResolver(notificationTemplateSchema),
    defaultValues: {
      template_type: 'booking_confirmation',
      notification_type: 'email',
      is_active: true,
      is_default: false,
    },
  })

  const watchedValues = watch()

  const handleCreateTemplate = () => {
    setSelectedTemplate(null)
    reset({
      template_type: 'booking_confirmation',
      notification_type: 'email',
      is_active: true,
      is_default: false,
    })
    toggleCreateModal()
  }

  const handleEditTemplate = (template: NotificationTemplate) => {
    setSelectedTemplate(template)
    reset({
      name: template.name,
      template_type: template.template_type,
      notification_type: template.notification_type,
      subject: template.subject || '',
      message: template.message,
      is_active: template.is_active,
      is_default: template.is_default,
    })
    toggleEditModal()
  }

  const handleDeleteTemplate = (template: NotificationTemplate) => {
    setSelectedTemplate(template)
    toggleDeleteDialog()
  }

  const handleTestTemplate = (template: NotificationTemplate) => {
    setSelectedTemplate(template)
    toggleTestModal()
  }

  const onSubmitCreate = (data: NotificationTemplateFormData) => {
    createNotificationTemplate(data)
    toggleCreateModal()
  }

  const onSubmitEdit = (data: NotificationTemplateFormData) => {
    if (selectedTemplate) {
      updateNotificationTemplate({ id: selectedTemplate.id, data })
      toggleEditModal()
    }
  }

  const confirmDelete = () => {
    if (selectedTemplate) {
      deleteNotificationTemplate(selectedTemplate.id)
      setSelectedTemplate(null)
      toggleDeleteDialog()
    }
  }

  const handleTest = () => {
    if (selectedTemplate) {
      testNotificationTemplate(selectedTemplate.id)
      toggleTestModal()
    }
  }

  const getTemplateIcon = (type: string) => {
    return type === 'email' ? (
      <Mail className="h-5 w-5 text-primary-600" />
    ) : (
      <MessageSquare className="h-5 w-5 text-primary-600" />
    )
  }

  if (notificationTemplatesLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title="Notification Templates"
        subtitle="Create and manage email and SMS templates for automated communications"
        breadcrumbs={[
          { label: 'Notifications', href: ROUTES.NOTIFICATIONS },
          { label: 'Templates', current: true },
        ]}
        action={
          <Button
            onClick={handleCreateTemplate}
            leftIcon={<Plus className="h-4 w-4" />}
          >
            Create Template
          </Button>
        }
      />

      <Container>
        {!notificationTemplates || notificationTemplates.length === 0 ? (
          <EmptyState
            icon={<Mail className="h-12 w-12" />}
            title="No templates yet"
            description="Create your first notification template to customize your automated communications"
            action={{
              label: 'Create Template',
              onClick: handleCreateTemplate,
            }}
          />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {notificationTemplates.map((template) => (
              <Card
                key={template.id}
                className="group hover:shadow-medium transition-all duration-200"
              >
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex items-center space-x-3">
                      <div className="p-2 bg-primary-100 rounded-lg">
                        {getTemplateIcon(template.notification_type)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <h3 className="text-lg font-semibold text-secondary-900 group-hover:text-primary-900 transition-colors">
                          {template.name}
                        </h3>
                        <p className="text-sm text-secondary-600">
                          {template.template_type_display}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center space-x-1">
                      <Badge variant={template.is_active ? 'success' : 'secondary'} size="sm">
                        {template.is_active ? 'Active' : 'Inactive'}
                      </Badge>
                      {template.is_default && (
                        <Badge variant="primary" size="sm">Default</Badge>
                      )}
                      <div className="relative group/menu">
                        <Button variant="ghost" size="sm">
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                        <div className="absolute right-0 top-full mt-1 w-48 bg-white rounded-lg shadow-strong border border-secondary-200 py-1 opacity-0 invisible group-hover/menu:opacity-100 group-hover/menu:visible transition-all duration-200 z-10">
                          <button
                            onClick={() => handleTestTemplate(template)}
                            className="w-full px-3 py-2 text-left text-sm text-secondary-700 hover:bg-secondary-50 flex items-center space-x-2"
                          >
                            <TestTube className="h-4 w-4" />
                            <span>Test</span>
                          </button>
                          <button
                            onClick={() => handleEditTemplate(template)}
                            className="w-full px-3 py-2 text-left text-sm text-secondary-700 hover:bg-secondary-50 flex items-center space-x-2"
                          >
                            <Edit className="h-4 w-4" />
                            <span>Edit</span>
                          </button>
                          <button
                            onClick={() => {
                              // TODO: Implement duplicate template
                            }}
                            className="w-full px-3 py-2 text-left text-sm text-secondary-700 hover:bg-secondary-50 flex items-center space-x-2"
                          >
                            <Copy className="h-4 w-4" />
                            <span>Duplicate</span>
                          </button>
                          <hr className="my-1 border-secondary-100" />
                          <button
                            onClick={() => handleDeleteTemplate(template)}
                            className="w-full px-3 py-2 text-left text-sm text-error-600 hover:bg-error-50 flex items-center space-x-2"
                          >
                            <Trash2 className="h-4 w-4" />
                            <span>Delete</span>
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                </CardHeader>

                <CardContent>
                  <div className="space-y-4">
                    <div>
                      <Badge variant="secondary" size="sm">
                        {template.notification_type_display}
                      </Badge>
                    </div>

                    {template.subject && (
                      <div>
                        <p className="text-sm font-medium text-secondary-900 mb-1">Subject:</p>
                        <p className="text-sm text-secondary-600 line-clamp-2">
                          {template.subject}
                        </p>
                      </div>
                    )}

                    <div>
                      <p className="text-sm font-medium text-secondary-900 mb-1">Message:</p>
                      <p className="text-sm text-secondary-600 line-clamp-3">
                        {template.message}
                      </p>
                    </div>

                    <div className="flex space-x-2 pt-2 border-t border-secondary-100">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleTestTemplate(template)}
                        className="flex-1"
                      >
                        <TestTube className="h-4 w-4 mr-2" />
                        Test
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleEditTemplate(template)}
                        className="flex-1"
                      >
                        <Edit className="h-4 w-4 mr-2" />
                        Edit
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </Container>

      {/* Create Template Modal */}
      <Modal
        isOpen={showCreateModal}
        onClose={toggleCreateModal}
        title="Create Notification Template"
        size="lg"
      >
        <form onSubmit={handleSubmit(onSubmitCreate)} className="space-y-6">
          <Input
            {...register('name')}
            label="Template Name"
            placeholder="e.g., Custom Booking Confirmation"
            error={errors.name?.message}
            required
          />

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Select
              options={templateTypeOptions}
              value={watchedValues.template_type}
              onChange={(value) => register('template_type').onChange({ target: { value } })}
              label="Template Type"
              error={errors.template_type?.message}
              required
            />

            <Select
              options={notificationTypeOptions}
              value={watchedValues.notification_type}
              onChange={(value) => register('notification_type').onChange({ target: { value } })}
              label="Notification Type"
              error={errors.notification_type?.message}
              required
            />
          </div>

          {watchedValues.notification_type === 'email' && (
            <Input
              {...register('subject')}
              label="Subject"
              placeholder="Email subject with {{placeholders}}"
              error={errors.subject?.message}
              required
            />
          )}

          <Textarea
            {...register('message')}
            label="Message"
            placeholder="Message content with {{placeholders}}"
            error={errors.message?.message}
            rows={8}
            required
          />

          <div className="bg-info-50 border border-info-200 rounded-lg p-4">
            <h4 className="font-medium text-info-800 mb-2">Available Placeholders</h4>
            <div className="grid grid-cols-2 gap-2 text-sm text-info-700">
              <div>
                <p className="font-medium mb-1">Booking Info:</p>
                <ul className="space-y-1 text-xs">
                  <li>{`{{invitee_name}}`}</li>
                  <li>{`{{invitee_email}}`}</li>
                  <li>{`{{organizer_name}}`}</li>
                  <li>{`{{event_name}}`}</li>
                  <li>{`{{start_time}}`}</li>
                  <li>{`{{duration}}`}</li>
                </ul>
              </div>
              <div>
                <p className="font-medium mb-1">Meeting Info:</p>
                <ul className="space-y-1 text-xs">
                  <li>{`{{meeting_link}}`}</li>
                  <li>{`{{meeting_id}}`}</li>
                  <li>{`{{meeting_password}}`}</li>
                  <li>{`{{location}}`}</li>
                  <li>{`{{timezone}}`}</li>
                </ul>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <Checkbox
              {...register('is_active')}
              label="Active"
              description="Enable this template"
            />

            <Checkbox
              {...register('is_default')}
              label="Default Template"
              description="Use as default for this type"
            />
          </div>

          <div className="flex space-x-3">
            <Button type="button" variant="outline" onClick={toggleCreateModal} className="flex-1">
              Cancel
            </Button>
            <Button
              type="submit"
              loading={isNotificationActionLoading}
              disabled={isNotificationActionLoading}
              className="flex-1"
            >
              Create Template
            </Button>
          </div>
        </form>
      </Modal>

      {/* Edit Template Modal */}
      <Modal
        isOpen={showEditModal}
        onClose={toggleEditModal}
        title="Edit Notification Template"
        size="lg"
      >
        <form onSubmit={handleSubmit(onSubmitEdit)} className="space-y-6">
          <Input
            {...register('name')}
            label="Template Name"
            placeholder="e.g., Custom Booking Confirmation"
            error={errors.name?.message}
            required
          />

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Select
              options={templateTypeOptions}
              value={watchedValues.template_type}
              onChange={(value) => register('template_type').onChange({ target: { value } })}
              label="Template Type"
              error={errors.template_type?.message}
              required
            />

            <Select
              options={notificationTypeOptions}
              value={watchedValues.notification_type}
              onChange={(value) => register('notification_type').onChange({ target: { value } })}
              label="Notification Type"
              error={errors.notification_type?.message}
              required
            />
          </div>

          {watchedValues.notification_type === 'email' && (
            <Input
              {...register('subject')}
              label="Subject"
              placeholder="Email subject with {{placeholders}}"
              error={errors.subject?.message}
              required
            />
          )}

          <Textarea
            {...register('message')}
            label="Message"
            placeholder="Message content with {{placeholders}}"
            error={errors.message?.message}
            rows={8}
            required
          />

          <div className="grid grid-cols-2 gap-4">
            <Checkbox
              {...register('is_active')}
              label="Active"
              description="Enable this template"
            />

            <Checkbox
              {...register('is_default')}
              label="Default Template"
              description="Use as default for this type"
            />
          </div>

          <div className="flex space-x-3">
            <Button type="button" variant="outline" onClick={toggleEditModal} className="flex-1">
              Cancel
            </Button>
            <Button
              type="submit"
              loading={isNotificationActionLoading}
              disabled={isNotificationActionLoading}
              className="flex-1"
            >
              Save Changes
            </Button>
          </div>
        </form>
      </Modal>

      {/* Test Template Modal */}
      <Modal
        isOpen={showTestModal}
        onClose={toggleTestModal}
        title="Test Notification Template"
        size="md"
      >
        {selectedTemplate && (
          <div className="space-y-6">
            <div className="text-center">
              <div className="p-3 bg-primary-100 rounded-lg text-primary-600 w-fit mx-auto mb-4">
                {getTemplateIcon(selectedTemplate.notification_type)}
              </div>
              <h3 className="text-lg font-semibold text-secondary-900 mb-2">
                {selectedTemplate.name}
              </h3>
              <p className="text-secondary-600">
                Send a test {selectedTemplate.notification_type} to verify the template works correctly
              </p>
            </div>

            <div className="bg-warning-50 border border-warning-200 rounded-lg p-4">
              <h4 className="font-medium text-warning-800 mb-2">Test Information</h4>
              <ul className="text-sm text-warning-700 space-y-1 list-disc list-inside">
                <li>Test will be sent to your account email</li>
                <li>Subject line will be prefixed with [TEST]</li>
                <li>Mock data will be used for placeholders</li>
                <li>No real booking data will be used</li>
              </ul>
            </div>

            <div className="flex space-x-3">
              <Button variant="outline" onClick={toggleTestModal} className="flex-1">
                Cancel
              </Button>
              <Button
                onClick={handleTest}
                loading={isNotificationActionLoading}
                disabled={isNotificationActionLoading}
                className="flex-1"
                leftIcon={<TestTube className="h-4 w-4" />}
              >
                Send Test
              </Button>
            </div>
          </div>
        )}
      </Modal>

      {/* Delete Confirmation */}
      <ConfirmDialog
        isOpen={showDeleteDialog}
        onClose={toggleDeleteDialog}
        onConfirm={confirmDelete}
        title="Delete Template"
        message={`Are you sure you want to delete "${selectedTemplate?.name}"? This action cannot be undone.`}
        confirmText="Delete"
        variant="danger"
      />
    </div>
  )
}