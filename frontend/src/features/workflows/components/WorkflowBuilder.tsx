import React from 'react'
import { Plus, ArrowDown, Settings, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { cn } from '@/utils/cn'

interface WorkflowAction {
  id: string
  name: string
  action_type: string
  order: number
  is_active: boolean
}

interface WorkflowBuilderProps {
  actions: WorkflowAction[]
  onAddAction: () => void
  onEditAction: (actionId: string) => void
  onDeleteAction: (actionId: string) => void
  onReorderActions: (actions: WorkflowAction[]) => void
  className?: string
}

export function WorkflowBuilder({
  actions,
  onAddAction,
  onEditAction,
  onDeleteAction,
  onReorderActions,
  className,
}: WorkflowBuilderProps) {
  const getActionTypeColor = (actionType: string) => {
    switch (actionType) {
      case 'send_email':
        return 'bg-blue-100 text-blue-800'
      case 'send_sms':
        return 'bg-green-100 text-green-800'
      case 'webhook':
        return 'bg-purple-100 text-purple-800'
      case 'update_booking':
        return 'bg-orange-100 text-orange-800'
      default:
        return 'bg-secondary-100 text-secondary-800'
    }
  }

  const getActionTypeLabel = (actionType: string) => {
    switch (actionType) {
      case 'send_email':
        return 'Email'
      case 'send_sms':
        return 'SMS'
      case 'webhook':
        return 'Webhook'
      case 'update_booking':
        return 'Update Booking'
      default:
        return actionType
    }
  }

  return (
    <div className={cn('space-y-4', className)}>
      {/* Trigger */}
      <Card>
        <CardContent className="p-4">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 bg-primary-600 rounded-full flex items-center justify-center">
              <span className="text-white text-sm font-bold">T</span>
            </div>
            <div>
              <p className="font-medium text-secondary-900">Workflow Trigger</p>
              <p className="text-sm text-secondary-600">When the specified event occurs</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Actions */}
      {actions.map((action, index) => (
        <div key={action.id} className="relative">
          {/* Connector Line */}
          {index > 0 && (
            <div className="absolute -top-4 left-4 w-0.5 h-4 bg-secondary-300" />
          )}
          
          <Card className={cn(
            'transition-all duration-200',
            !action.is_active && 'opacity-60'
          )}>
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-8 h-8 bg-secondary-100 rounded-full flex items-center justify-center">
                    <span className="text-secondary-600 text-sm font-bold">{index + 1}</span>
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center space-x-2">
                      <p className="font-medium text-secondary-900">{action.name}</p>
                      <Badge 
                        variant="secondary" 
                        size="sm"
                        className={getActionTypeColor(action.action_type)}
                      >
                        {getActionTypeLabel(action.action_type)}
                      </Badge>
                      {!action.is_active && (
                        <Badge variant="secondary" size="sm">Inactive</Badge>
                      )}
                    </div>
                    <p className="text-sm text-secondary-600">
                      Order: {action.order}
                    </p>
                  </div>
                </div>
                
                <div className="flex items-center space-x-2">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => onEditAction(action.id)}
                  >
                    <Settings className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => onDeleteAction(action.id)}
                    className="text-error-600 hover:text-error-700"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Connector Arrow */}
          {index < actions.length - 1 && (
            <div className="flex justify-center py-2">
              <ArrowDown className="h-4 w-4 text-secondary-400" />
            </div>
          )}
        </div>
      ))}

      {/* Add Action Button */}
      <div className="flex justify-center">
        <Button
          variant="outline"
          onClick={onAddAction}
          leftIcon={<Plus className="h-4 w-4" />}
          className="border-dashed"
        >
          Add Action
        </Button>
      </div>
    </div>
  )
}