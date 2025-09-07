import React, { useState } from 'react'
import { Plus, Trash2, ChevronDown } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Input'
import { Select } from '@/components/ui/Select'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { cn } from '@/utils/cn'

interface Condition {
  field: string
  operator: string
  value: any
}

interface ConditionGroup {
  operator: 'AND' | 'OR'
  rules: Condition[]
}

interface ConditionBuilderProps {
  conditions: ConditionGroup[]
  onChange: (conditions: ConditionGroup[]) => void
  className?: string
}

const fieldOptions = [
  { value: 'invitee_email', label: 'Invitee Email' },
  { value: 'invitee_name', label: 'Invitee Name' },
  { value: 'event_type_name', label: 'Event Type Name' },
  { value: 'duration', label: 'Duration (minutes)' },
  { value: 'attendee_count', label: 'Attendee Count' },
  { value: 'booking_hour', label: 'Booking Hour' },
  { value: 'booking_day_of_week', label: 'Day of Week' },
  { value: 'is_weekend', label: 'Is Weekend' },
  { value: 'invitee_domain', label: 'Invitee Email Domain' },
  { value: 'organizer_company', label: 'Organizer Company' },
]

const operatorOptions = [
  { value: 'equals', label: 'Equals' },
  { value: 'not_equals', label: 'Not Equals' },
  { value: 'greater_than', label: 'Greater Than' },
  { value: 'less_than', label: 'Less Than' },
  { value: 'contains', label: 'Contains' },
  { value: 'not_contains', label: 'Does Not Contain' },
  { value: 'starts_with', label: 'Starts With' },
  { value: 'ends_with', label: 'Ends With' },
  { value: 'is_empty', label: 'Is Empty' },
  { value: 'is_not_empty', label: 'Is Not Empty' },
]

const groupOperatorOptions = [
  { value: 'AND', label: 'AND (all conditions must be true)' },
  { value: 'OR', label: 'OR (any condition can be true)' },
]

export function ConditionBuilder({ conditions, onChange, className }: ConditionBuilderProps) {
  const addConditionGroup = () => {
    const newGroup: ConditionGroup = {
      operator: 'AND',
      rules: [{ field: 'invitee_email', operator: 'equals', value: '' }]
    }
    onChange([...conditions, newGroup])
  }

  const removeConditionGroup = (groupIndex: number) => {
    const newConditions = conditions.filter((_, index) => index !== groupIndex)
    onChange(newConditions)
  }

  const updateConditionGroup = (groupIndex: number, updates: Partial<ConditionGroup>) => {
    const newConditions = conditions.map((group, index) => 
      index === groupIndex ? { ...group, ...updates } : group
    )
    onChange(newConditions)
  }

  const addRule = (groupIndex: number) => {
    const newRule: Condition = { field: 'invitee_email', operator: 'equals', value: '' }
    const newConditions = conditions.map((group, index) => 
      index === groupIndex 
        ? { ...group, rules: [...group.rules, newRule] }
        : group
    )
    onChange(newConditions)
  }

  const removeRule = (groupIndex: number, ruleIndex: number) => {
    const newConditions = conditions.map((group, index) => 
      index === groupIndex 
        ? { ...group, rules: group.rules.filter((_, rIndex) => rIndex !== ruleIndex) }
        : group
    )
    onChange(newConditions)
  }

  const updateRule = (groupIndex: number, ruleIndex: number, updates: Partial<Condition>) => {
    const newConditions = conditions.map((group, gIndex) => 
      gIndex === groupIndex 
        ? {
            ...group,
            rules: group.rules.map((rule, rIndex) => 
              rIndex === ruleIndex ? { ...rule, ...updates } : rule
            )
          }
        : group
    )
    onChange(newConditions)
  }

  const needsValue = (operator: string) => {
    return !['is_empty', 'is_not_empty'].includes(operator)
  }

  return (
    <div className={cn('space-y-4', className)}>
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-secondary-900">Conditions</h3>
        <Button
          variant="outline"
          size="sm"
          onClick={addConditionGroup}
          leftIcon={<Plus className="h-4 w-4" />}
        >
          Add Condition Group
        </Button>
      </div>

      {conditions.length === 0 ? (
        <Card>
          <CardContent className="p-8 text-center">
            <p className="text-secondary-500 mb-4">No conditions set</p>
            <p className="text-sm text-secondary-400 mb-4">
              This action will run for all bookings. Add conditions to make it more specific.
            </p>
            <Button
              variant="outline"
              onClick={addConditionGroup}
              leftIcon={<Plus className="h-4 w-4" />}
            >
              Add First Condition
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-4">
          {conditions.map((group, groupIndex) => (
            <Card key={groupIndex} variant="outlined">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <h4 className="font-medium text-secondary-900">
                    Condition Group {groupIndex + 1}
                  </h4>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => removeConditionGroup(groupIndex)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <Select
                  options={groupOperatorOptions}
                  value={group.operator}
                  onChange={(value) => updateConditionGroup(groupIndex, { operator: value as 'AND' | 'OR' })}
                  label="Group Operator"
                />

                <div className="space-y-3">
                  {group.rules.map((rule, ruleIndex) => (
                    <div key={ruleIndex} className="flex items-end space-x-3 p-3 bg-secondary-50 rounded-lg">
                      <div className="flex-1 grid grid-cols-1 md:grid-cols-3 gap-3">
                        <Select
                          options={fieldOptions}
                          value={rule.field}
                          onChange={(value) => updateRule(groupIndex, ruleIndex, { field: value as string })}
                          label="Field"
                          required
                        />

                        <Select
                          options={operatorOptions}
                          value={rule.operator}
                          onChange={(value) => updateRule(groupIndex, ruleIndex, { operator: value as string })}
                          label="Operator"
                          required
                        />

                        {needsValue(rule.operator) && (
                          <Input
                            label="Value"
                            value={rule.value || ''}
                            onChange={(e) => updateRule(groupIndex, ruleIndex, { value: e.target.value })}
                            placeholder="Comparison value"
                            required
                          />
                        )}
                      </div>

                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => removeRule(groupIndex, ruleIndex)}
                        className="mb-1"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  ))}
                </div>

                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => addRule(groupIndex)}
                  leftIcon={<Plus className="h-4 w-4" />}
                >
                  Add Rule
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {conditions.length > 0 && (
        <div className="bg-info-50 border border-info-200 rounded-lg p-4">
          <h4 className="font-medium text-info-800 mb-2">How Conditions Work</h4>
          <ul className="text-sm text-info-700 space-y-1 list-disc list-inside">
            <li>All condition groups must be true for the action to execute</li>
            <li>Within each group, rules are combined using the group operator (AND/OR)</li>
            <li>Use multiple groups for complex logic like "(A AND B) OR (C AND D)"</li>
          </ul>
        </div>
      )}
    </div>
  )
}