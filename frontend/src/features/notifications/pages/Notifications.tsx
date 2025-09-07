import React, { useState } from 'react'
import { Bell, Plus, Mail, MessageSquare, Settings, TrendingUp, AlertTriangle, CheckCircle, Clock, Filter, Search } from 'lucide-react'
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
import { formatRelativeTime } from '@/utils/date'
import { formatNotificationType } from '@/utils/format'
import { formatNumber } from '@/utils/helpers'
import type { TableColumn } from '@/types'

const statusOptions = [
  { value: '', label: 'All Statuses' },
  { value: 'pending', label: 'Pending' },
  { value: 'sent', label: 'Sent' },
  { value: 'delivered', label: 'Delivered' },
  { value: 'failed', label: 'Failed' },
  { value: 'bounced', label: 'Bounced' },
]

const typeOptions = [
  { value: '', label: 'All Types' },
  { value: 'email', label: 'Email' },
  { value: 'sms', label: 'SMS' },
]

export default function Notifications() {
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
    notificationStats,
    resendNotification,
    isNotificationActionLoading,
  } = useNotifications()

  const { data: logsData, isLoading } = notificationLogs({
    ...filters,
    search: debouncedSearch || undefined,
  })

  const { data: stats, isLoading: statsLoading } = notificationStats()

  const logs = logsData?.results || []
  const totalCount = logsData?.count || 0

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'sent':
      case 'delivered':
        return <CheckCircle className="h-4 w-4 text-success-500" />
      case 'failed':
      case 'bounced':
        return <AlertTriangle className="h-4 w-4 text-error-500" />
      case 'pending':
        return <Clock className="h-4 w-4 text-warning-500" />
      default:
        return <Clock className="h-4 w-4 text-secondary-400" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'sent':
      case 'delivered':
        return 'success'
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
          <div>
            <p className="text-sm font-medium text-secondary-900">
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
      key: 'subject',
      label: 'Subject/Content',
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
          {getStatusIcon(log.status)}
          <Badge variant={getStatusColor(log.status) as any} size="sm">
            {log.status_display}
          </Badge>
        </div>
      ),
    },
    {
      key: 'delivery',
      label: 'Delivery',
      render: (_, log) => (
        <div className="text-sm text-secondary-600">
          {log.sent_at ? (
            <div>
              <p>Sent: {formatRelativeTime(log.sent_at)}</p>
              {log.delivered_at && (
                <p className="text-xs text-success-600">
                  Delivered: {formatRelativeTime(log.delivered_at)}
                </p>
              )}
              {log.opened_at && (
                <p className="text-xs text-primary-600">
                  Opened: {formatRelativeTime(log.opened_at)}
                </p>
              )}
            </div>
          ) : (
            <span className="text-secondary-500">Not sent</span>
          )}
        </div>
      ),
    },
    {
      key: 'retry_count',
      label: 'Retries',
      render: (_, log) => (
        <div className="text-center">
          <span className="text-sm font-medium text-secondary-900">
            {log.retry_count}
          </span>
          {log.retry_count > 0 && (
            <p className="text-xs text-warning-600">
              {log.retry_count} attempts
            </p>
          )}
        </div>
      ),
    },
    {
      key: 'created_at',
      label: 'Created',
      render: (_, log) => (
        <span className="text-sm text-secondary-600">
          {formatRelativeTime(log.created_at)}
        </span>
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

  return (
    <div className="space-y-8">
      <PageHeader
        title="Notifications"
        subtitle="Monitor and manage all your notification communications"
        action={
          <div className="flex space-x-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => window.location.href = ROUTES.NOTIFICATION_TEMPLATES}
              leftIcon={<Settings className="h-4 w-4" />}
            >
              Templates
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => window.location.href = ROUTES.NOTIFICATION_PREFERENCES}
              leftIcon={<Bell className="h-4 w-4" />}
            >
              Preferences
            </Button>
          </div>
        }
      />

      <Container>
        {/* Stats Overview */}
        {stats && !statsLoading && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <Card>
              <CardContent className="p-6">
                <div className="flex items-center">
                  <div className="flex-1">
                    <p className="text-sm font-medium text-secondary-600">Total Sent</p>
                    <p className="text-2xl font-bold text-secondary-900">
                      {formatNumber(stats.total_sent)}
                    </p>
                  </div>
                  <div className="p-3 bg-primary-100 rounded-lg">
                    <Bell className="h-6 w-6 text-primary-600" />
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-6">
                <div className="flex items-center">
                  <div className="flex-1">
                    <p className="text-sm font-medium text-secondary-600">Delivery Rate</p>
                    <p className="text-2xl font-bold text-secondary-900">
                      {stats.email_delivery_rate}%
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
                    <p className="text-sm font-medium text-secondary-600">Open Rate</p>
                    <p className="text-2xl font-bold text-secondary-900">
                      {stats.email_open_rate}%
                    </p>
                  </div>
                  <div className="p-3 bg-info-100 rounded-lg">
                    <Mail className="h-6 w-6 text-info-600" />
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-6">
                <div className="flex items-center">
                  <div className="flex-1">
                    <p className="text-sm font-medium text-secondary-600">Failed</p>
                    <p className="text-2xl font-bold text-secondary-900">
                      {formatNumber(stats.total_failed)}
                    </p>
                  </div>
                  <div className="p-3 bg-error-100 rounded-lg">
                    <AlertTriangle className="h-6 w-6 text-error-600" />
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Filters */}
        <Card className="mb-6">
          <CardContent className="p-6">
            <div className="flex items-center space-x-4">
              <div className="flex-1">
                <Input
                  type="text"
                  placeholder="Search notifications..."
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

        {/* Notifications Table */}
        {isLoading ? (
          <div className="flex items-center justify-center min-h-[400px]">
            <LoadingSpinner size="lg" />
          </div>
        ) : logs.length === 0 ? (
          <EmptyState
            icon={<Bell className="h-12 w-12" />}
            title="No notifications yet"
            description="Notifications will appear here as they are sent to your contacts"
          />
        ) : (
          <Card>
            <CardHeader title="Notification History" />
            <CardContent>
              <DataTable
                columns={columns}
                data={logs}
                loading={isLoading}
                emptyMessage="No notifications found"
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