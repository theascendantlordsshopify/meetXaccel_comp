import React from 'react'
import { TrendingUp, Mail, MessageSquare, CheckCircle, XCircle, Eye, MousePointer } from 'lucide-react'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { useNotifications } from '@/hooks/useNotifications'
import { formatNumber, formatPercentage } from '@/utils/helpers'

export function NotificationStats() {
  const { notificationStats } = useNotifications()
  const { data: stats, isLoading } = notificationStats()

  if (isLoading) {
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

  if (!stats) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="text-center text-secondary-500">
            No notification statistics available
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      {/* Total Notifications */}
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center">
            <div className="flex-1">
              <p className="text-sm font-medium text-secondary-600">Total Sent</p>
              <p className="text-2xl font-bold text-secondary-900">
                {formatNumber(stats.total_sent)}
              </p>
              <p className="text-xs text-secondary-500">
                {formatNumber(stats.email_count)} emails, {formatNumber(stats.sms_count)} SMS
              </p>
            </div>
            <div className="p-3 bg-primary-100 rounded-lg">
              <TrendingUp className="h-6 w-6 text-primary-600" />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Delivery Rate */}
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center">
            <div className="flex-1">
              <p className="text-sm font-medium text-secondary-600">Delivery Rate</p>
              <p className="text-2xl font-bold text-secondary-900">
                {formatPercentage(stats.email_delivery_rate)}
              </p>
              <p className="text-xs text-secondary-500">
                {formatNumber(stats.total_delivered)} delivered
              </p>
            </div>
            <div className="p-3 bg-success-100 rounded-lg">
              <CheckCircle className="h-6 w-6 text-success-600" />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Open Rate */}
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center">
            <div className="flex-1">
              <p className="text-sm font-medium text-secondary-600">Open Rate</p>
              <p className="text-2xl font-bold text-secondary-900">
                {formatPercentage(stats.email_open_rate)}
              </p>
              <p className="text-xs text-secondary-500">
                {formatNumber(stats.total_opened)} opened
              </p>
            </div>
            <div className="p-3 bg-info-100 rounded-lg">
              <Eye className="h-6 w-6 text-info-600" />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Click Rate */}
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center">
            <div className="flex-1">
              <p className="text-sm font-medium text-secondary-600">Click Rate</p>
              <p className="text-2xl font-bold text-secondary-900">
                {formatPercentage(stats.email_click_rate)}
              </p>
              <p className="text-xs text-secondary-500">
                {formatNumber(stats.total_clicked)} clicked
              </p>
            </div>
            <div className="p-3 bg-warning-100 rounded-lg">
              <MousePointer className="h-6 w-6 text-warning-600" />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Recent Activity */}
      <Card className="md:col-span-2">
        <CardHeader title="Recent Activity" />
        <CardContent>
          <div className="grid grid-cols-3 gap-4 text-center">
            <div>
              <p className="text-2xl font-bold text-secondary-900">
                {formatNumber(stats.recent_activity?.total || 0)}
              </p>
              <p className="text-sm text-secondary-600">Total (7 days)</p>
            </div>
            <div>
              <p className="text-2xl font-bold text-success-600">
                {formatNumber(stats.recent_activity?.sent || 0)}
              </p>
              <p className="text-sm text-secondary-600">Sent</p>
            </div>
            <div>
              <p className="text-2xl font-bold text-error-600">
                {formatNumber(stats.recent_activity?.failed || 0)}
              </p>
              <p className="text-sm text-secondary-600">Failed</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Top Templates */}
      <Card className="md:col-span-2">
        <CardHeader title="Most Used Templates" />
        <CardContent>
          {stats.top_templates && stats.top_templates.length > 0 ? (
            <div className="space-y-3">
              {stats.top_templates.slice(0, 5).map((template, index) => (
                <div key={index} className="flex items-center justify-between">
                  <span className="text-sm text-secondary-900">{template.template__name}</span>
                  <Badge variant="secondary" size="sm">
                    {formatNumber(template.usage_count)} uses
                  </Badge>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-secondary-500">No template usage data available</p>
          )}
        </CardContent>
      </Card>
    </div>
  )
}