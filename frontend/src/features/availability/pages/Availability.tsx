import React, { useState } from 'react'
import { Clock, Plus, Calendar, Settings, BarChart3 } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { Container } from '@/components/layout/Container'
import { Modal } from '@/components/ui/Modal'
import { useAvailability } from '@/hooks/useAvailability'
import { useToggle } from '@/hooks/useToggle'
import { formatTime } from '@/utils/date'
import { getDayName } from '@/utils/date'
import type { AvailabilityRule } from '@/types'

export default function Availability() {
  const {
    availabilityRules,
    rulesLoading,
    dateOverrides,
    overridesLoading,
    blockedTimes,
    blockedTimesLoading,
    recurringBlocks,
    recurringBlocksLoading,
    availabilityStats,
    statsLoading,
  } = useAvailability()

  const [showCreateRuleModal, { toggle: toggleCreateRuleModal }] = useToggle()
  const [showStatsModal, { toggle: toggleStatsModal }] = useToggle()

  const isLoading = rulesLoading || overridesLoading || blockedTimesLoading || recurringBlocksLoading

  // Group rules by day of week
  const rulesByDay = React.useMemo(() => {
    if (!availabilityRules) return {}
    
    const grouped: Record<number, AvailabilityRule[]> = {}
    availabilityRules.forEach(rule => {
      if (!grouped[rule.day_of_week]) {
        grouped[rule.day_of_week] = []
      }
      grouped[rule.day_of_week].push(rule)
    })
    
    return grouped
  }, [availabilityRules])

  const weekDays = [
    { value: 0, label: 'Monday' },
    { value: 1, label: 'Tuesday' },
    { value: 2, label: 'Wednesday' },
    { value: 3, label: 'Thursday' },
    { value: 4, label: 'Friday' },
    { value: 5, label: 'Saturday' },
    { value: 6, label: 'Sunday' },
  ]

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title="Availability"
        subtitle="Set your available hours and manage your schedule"
        action={
          <div className="flex space-x-2">
            <Button
              variant="outline"
              size="sm"
              onClick={toggleStatsModal}
              leftIcon={<BarChart3 className="h-4 w-4" />}
            >
              View Stats
            </Button>
            <Button
              onClick={toggleCreateRuleModal}
              leftIcon={<Plus className="h-4 w-4" />}
            >
              Add Hours
            </Button>
          </div>
        }
      />

      <Container>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Weekly Schedule */}
          <div className="lg:col-span-2">
            <Card>
              <CardHeader title="Weekly Schedule" />
              <CardContent>
                {availabilityRules?.length === 0 ? (
                  <EmptyState
                    icon={<Clock className="h-12 w-12" />}
                    title="No availability set"
                    description="Add your available hours to start accepting bookings"
                    action={{
                      label: 'Add Available Hours',
                      onClick: toggleCreateRuleModal,
                    }}
                  />
                ) : (
                  <div className="space-y-4">
                    {weekDays.map(day => {
                      const dayRules = rulesByDay[day.value] || []
                      
                      return (
                        <div key={day.value} className="flex items-center justify-between p-4 border border-secondary-200 rounded-lg">
                          <div className="flex items-center space-x-4">
                            <div className="w-20">
                              <p className="font-medium text-secondary-900">{day.label}</p>
                            </div>
                            <div className="flex-1">
                              {dayRules.length === 0 ? (
                                <span className="text-secondary-500">Unavailable</span>
                              ) : (
                                <div className="flex flex-wrap gap-2">
                                  {dayRules.map(rule => (
                                    <Badge
                                      key={rule.id}
                                      variant={rule.is_active ? 'success' : 'secondary'}
                                      className="text-xs"
                                    >
                                      {formatTime(rule.start_time, 'HH:mm')} - {formatTime(rule.end_time, 'HH:mm')}
                                    </Badge>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>
                          
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              // TODO: Open edit modal for this day
                            }}
                          >
                            <Settings className="h-4 w-4" />
                          </Button>
                        </div>
                      )
                    })}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Quick Stats */}
            {availabilityStats && (
              <Card>
                <CardHeader title="Quick Stats" />
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex justify-between">
                      <span className="text-secondary-600">Active Rules:</span>
                      <span className="font-medium text-secondary-900">
                        {availabilityStats.active_rules}
                      </span>
                    </div>
                    
                    <div className="flex justify-between">
                      <span className="text-secondary-600">Weekly Hours:</span>
                      <span className="font-medium text-secondary-900">
                        {availabilityStats.average_weekly_hours}h
                      </span>
                    </div>
                    
                    <div className="flex justify-between">
                      <span className="text-secondary-600">Busiest Day:</span>
                      <span className="font-medium text-secondary-900">
                        {availabilityStats.busiest_day}
                      </span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Date Overrides */}
            <Card>
              <CardHeader
                title="Date Overrides"
                subtitle={`${dateOverrides?.length || 0} special dates`}
                action={
                  <Button variant="outline" size="sm">
                    <Plus className="h-4 w-4" />
                  </Button>
                }
              />
              <CardContent>
                {dateOverrides?.length === 0 ? (
                  <p className="text-secondary-500 text-sm">No date overrides</p>
                ) : (
                  <div className="space-y-2">
                    {dateOverrides?.slice(0, 3).map(override => (
                      <div key={override.id} className="flex items-center justify-between text-sm">
                        <span className="text-secondary-900">
                          {formatDate(override.date)}
                        </span>
                        <Badge
                          variant={override.is_available ? 'success' : 'error'}
                          size="sm"
                        >
                          {override.is_available ? 'Available' : 'Blocked'}
                        </Badge>
                      </div>
                    ))}
                    {dateOverrides && dateOverrides.length > 3 && (
                      <p className="text-xs text-secondary-500 text-center">
                        +{dateOverrides.length - 3} more
                      </p>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Blocked Times */}
            <Card>
              <CardHeader
                title="Blocked Times"
                subtitle={`${blockedTimes?.length || 0} blocked periods`}
                action={
                  <Button variant="outline" size="sm">
                    <Plus className="h-4 w-4" />
                  </Button>
                }
              />
              <CardContent>
                {blockedTimes?.length === 0 ? (
                  <p className="text-secondary-500 text-sm">No blocked times</p>
                ) : (
                  <div className="space-y-2">
                    {blockedTimes?.slice(0, 3).map(block => (
                      <div key={block.id} className="text-sm">
                        <p className="text-secondary-900 font-medium">
                          {formatDate(block.start_datetime)}
                        </p>
                        <p className="text-secondary-600">
                          {formatTime(block.start_datetime)} - {formatTime(block.end_datetime)}
                        </p>
                        {block.reason && (
                          <p className="text-xs text-secondary-500">{block.reason}</p>
                        )}
                      </div>
                    ))}
                    {blockedTimes && blockedTimes.length > 3 && (
                      <p className="text-xs text-secondary-500 text-center">
                        +{blockedTimes.length - 3} more
                      </p>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </Container>

      {/* Create Rule Modal */}
      <Modal
        isOpen={showCreateRuleModal}
        onClose={toggleCreateRuleModal}
        title="Add Available Hours"
        size="md"
      >
        <div className="space-y-6">
          <p className="text-secondary-600">
            Set your available hours for a specific day of the week.
          </p>
          
          {/* TODO: Add create rule form */}
          <div className="text-center py-8">
            <p className="text-secondary-500">Create rule form coming soon...</p>
          </div>
          
          <div className="flex justify-end space-x-3">
            <Button variant="outline" onClick={toggleCreateRuleModal}>
              Cancel
            </Button>
            <Button>
              Save Hours
            </Button>
          </div>
        </div>
      </Modal>

      {/* Stats Modal */}
      <Modal
        isOpen={showStatsModal}
        onClose={toggleStatsModal}
        title="Availability Statistics"
        size="lg"
      >
        <div className="space-y-6">
          {statsLoading ? (
            <div className="flex items-center justify-center py-8">
              <LoadingSpinner size="lg" />
            </div>
          ) : availabilityStats ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-secondary-600">Total Rules</p>
                  <p className="text-2xl font-bold text-secondary-900">
                    {availabilityStats.total_rules}
                  </p>
                </div>
                
                <div>
                  <p className="text-sm text-secondary-600">Active Rules</p>
                  <p className="text-2xl font-bold text-success-600">
                    {availabilityStats.active_rules}
                  </p>
                </div>
                
                <div>
                  <p className="text-sm text-secondary-600">Weekly Hours</p>
                  <p className="text-2xl font-bold text-primary-600">
                    {availabilityStats.average_weekly_hours}h
                  </p>
                </div>
              </div>

              <div className="space-y-4">
                <div>
                  <p className="text-sm text-secondary-600 mb-2">Daily Hours</p>
                  <div className="space-y-2">
                    {Object.entries(availabilityStats.daily_hours).map(([day, hours]) => (
                      <div key={day} className="flex justify-between text-sm">
                        <span className="text-secondary-700">{day}</span>
                        <span className="font-medium text-secondary-900">{hours}h</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <p className="text-secondary-500">No statistics available</p>
          )}
        </div>
      </Modal>
    </div>
  )
}