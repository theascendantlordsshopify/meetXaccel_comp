import React, { useState } from 'react'
import { Bell, Mail, MessageSquare, RefreshCw, Download, Filter, Search, ExternalLink, TrendingUp } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { Container } from '@/components/layout/Container'
import { DataTable } from '@/components/shared/DataTable'
import { useNotifications } from '@/hooks/useNotifications'
import { useDebounce } from '@/hooks/useDebounce'
import { ROUTES } from '@/constants/routes'
import { formatRelativeTime, formatDateTime } from '@/utils/date'
import { formatNotificationType } from '@/utils/format'
import { cn } from '@/utils/cn'
import type { TableColumn } from '@/types'

const statusOptions = [
  { value: '', label: 'All Statuses' },
  { value: 'pending', label: 'Pending' },
  { value: 'sent', label: 'Sent' },
  { value: 'delivered', label: 'Delivered' },
  { value: 'failed', label: 'Failed' },
  { value: 'bounced', label: 'Bounced' },
  { value: 'opened', label: 'Opened' },
  { value: 'clicked', label: 'Clicked' },
]

const typeOptions = [
  { value: '', label: 'All Types' },
  { value: 'email', label: 'Email' },
  { value: 'sms', label: 'SMS' },
]

export default function NotificationLogs() {
  const [filters, setFilters] = useState({
    status: '',
    notification_type: '',
    search: '',
    page: 1,
    page_size: 20,
  })
  const [searchQuery, setSearchQuery] = useState('')

  const debouncedSearch = useDebounce(searchQuery, 300)

  const {
    notificationLogs,
    resendNotification,
    exportNotificationLogs,
    isNotificationActionLoading,
  } = useNotifications()

  const { data: logsData, isLoading, refetch } = notificationLogs({
    ...filters,
    search: debouncedSearch || undefined,
  })

  const logs = logsData?.results || []
  const totalCount = logsData?.count || 0

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'sent':
      case 'delivered':
        return '✅'
      case 'opened':
        return '👁️'
      case 'clicked':
        return '🖱️'
      case 'failed':
      case 'bounced':
        return '❌'
      case 'pending':
        return '⏳'
      default:
        return '⚪'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'sent':
      case 'delivered':
        return 'success'
      case 'opened':
      case 'clicked':
        return 'info'
      case 'failed':
      case 'bounced':
        return 'error'
      case 'pending':
        return 'warning'
      default:
        return 'secondary'
    }
  }

  const columns: TableColumn[] = [
    {
      key: 'recipient',
      label: 'Recipient',
      render: (_, log) => (
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-secondary-100 rounded-lg">
            {log.notification_type === 'email' ? (
              <Mail className="h-4 w-4 text-secondary-600" />
            ) : (
              <MessageSquare className="h-4 w-4 text-secondary-600" />
            )}
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium text-secondary-900 truncate">
              {log.recipient_email || log.recipient_phone}
            </p>
            <p className="text-xs text-secondary-500">
              {formatNotificationType(log.notification_type)}
            </p>
          </div>
        </div>
      ),
    },
    {
      key: 'content',
      label: 'Content',
      render: (_, log) => (
        <div className="max-w-xs">
          <p className="text-sm font-medium text-secondary-900 truncate">
            {log.subject || 'SMS Message'}
          </p>
          <p className="text-xs text-secondary-500 truncate">
            {log.template_name || 'Custom Message'}
          </p>
        </div>
      ),
    },
    {
      key: 'status',
      label: 'Status',
      render: (_, log) => (
        <div className="flex items-center space-x-2">
          <span className="text-lg">{getStatusIcon(log.status)}</span>
          <div>
            <Badge variant={getStatusColor(log.status) as any} size="sm">
              {log.status_display}
            </Badge>
            {log.retry_count > 0 && (
              <p className="text-xs text-warning-600 mt-1">
                {log.retry_count} retries
              </p>
            )}
          </div>
        </div>
      ),
    },
    {
      key: 'timeline',
      label: 'Timeline',
      render: (_, log) => (
        <div className="text-xs text-secondary-600 space-y-1">
          <div>Created: {formatRelativeTime(log.created_at)}</div>
          {log.sent_at && (
            <div className="text-success-600">Sent: {formatRelativeTime(log.sent_at)}</div>
          )}
          {log.delivered_at && (
            <div className="text-success-600">Delivered: {formatRelativeTime(log.delivered_at)}</div>
          )}
          {log.opened_at && (
            <div className="text-info-600">Opened: {formatRelativeTime(log.opened_at)}</div>
          )}
          {log.clicked_at && (
            <div className="text-info-600">Clicked: {formatRelativeTime(log.clicked_at)}</div>
          )}
        </div>
      ),
    },
    {
      key: 'actions',
      label: 'Actions',
      render: (_, log) => (
        <div className="flex items-center space-x-2">
          {log.status === 'failed' && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => resendNotification(log.id)}
              disabled={isNotificationActionLoading}
              title="Retry notification"
            >
              <TrendingUp className="h-4 w-4" />
            </Button>
          )}
          {log.booking_id && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => window.open(`/dashboard/bookings/${log.booking_id}`, '_blank')}
              title="View related booking"
            >
              <ExternalLink className="h-4 w-4" />
            </Button>
          )}
        </div>
      ),
    },
  ]

  const handleFilterChange = (key: string, value: any) => {
    setFilters(prev => ({
      ...prev,
      [key]: value,
      page: 1,
    }))
  }

  const handlePageChange = (page: number) => {
    setFilters(prev => ({ ...prev, page }))
  }

  const handleExport = () => {
    exportNotificationLogs()
  }

  const handleRefresh = () => {
    refetch()
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title="Notification Logs"
        subtitle="Monitor delivery status and performance of all notifications"
        breadcrumbs={[
          { label: 'Notifications', href: ROUTES.NOTIFICATIONS },
          { label: 'Logs', current: true },
        ]}
        action={
          <div className="flex space-x-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handleRefresh}
              leftIcon={<RefreshCw className="h-4 w-4" />}
            >
              Refresh
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleExport}
              leftIcon={<Download className="h-4 w-4" />}
            >
              Export
            </Button>
          </div>
        }
      />

      <Container>
        {/* Filters */}
        <Card className="mb-6">
          <CardContent className="p-6">
            <div className="flex items-center space-x-4">
              <div className="flex-1">
                <Input
                  type="text"
                  placeholder="Search by recipient, subject, or template..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  leftIcon={<Search className="h-4 w-4" />}
                  className="max-w-md"
                />
              </div>

              <Select
                options={statusOptions}
                value={filters.status}
                onChange={(value) => handleFilterChange('status', value)}
                placeholder="Filter by status"
                className="w-48"
              />

              <Select
                options={typeOptions}
                value={filters.notification_type}
                onChange={(value) => handleFilterChange('notification_type', value)}
                placeholder="Filter by type"
                className="w-48"
              />

              <Button
                variant="outline"
                size="sm"
                leftIcon={<Filter className="h-4 w-4" />}
              >
                More Filters
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Notification Logs Table */}
        {isLoading ? (
          <div className="flex items-center justify-center min-h-[400px]">
            <LoadingSpinner size="lg" />
          </div>
        ) : logs.length === 0 ? (
          <EmptyState
            icon={<Bell className="h-12 w-12" />}
            title="No notification logs"
            description="Notification delivery logs will appear here as communications are sent"
          />
        ) : (
          <Card>
            <CardHeader title="Notification History" />
            <CardContent>
              <DataTable
                columns={columns}
                data={logs}
                loading={isLoading}
                emptyMessage="No notification logs found"
                pagination={{
                  page: filters.page,
                  pageSize: filters.page_size,
                  total: totalCount,
                }}
                onPageChange={handlePageChange}
              />
            </CardContent>
          </Card>
        )}
      </Container>
    </div>
  )
}