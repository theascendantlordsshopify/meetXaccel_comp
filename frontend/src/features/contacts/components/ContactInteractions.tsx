import React from 'react'
import { Calendar, Mail, MessageSquare, User, Clock } from 'lucide-react'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { EmptyState } from '@/components/ui/EmptyState'
import { Avatar } from '@/components/shared/Avatar'
import { useContacts } from '@/hooks/useContacts'
import { formatRelativeTime } from '@/utils/date'
import { formatNotificationType } from '@/utils/format'
import type { Contact, ContactInteraction } from '@/types'

interface ContactInteractionsProps {
  contact: Contact
  className?: string
}

export function ContactInteractions({ contact, className }: ContactInteractionsProps) {
  const { useContactInteractions } = useContacts()
  const { data: interactions, isLoading } = useContactInteractions(contact.id)

  const getInteractionIcon = (type: string) => {
    switch (type) {
      case 'booking_created':
        return <Calendar className="h-4 w-4 text-success-500" />
      case 'booking_completed':
        return <Calendar className="h-4 w-4 text-primary-500" />
      case 'booking_cancelled':
        return <Calendar className="h-4 w-4 text-error-500" />
      case 'email_sent':
        return <Mail className="h-4 w-4 text-blue-500" />
      case 'note_added':
        return <MessageSquare className="h-4 w-4 text-secondary-500" />
      case 'manual_entry':
        return <User className="h-4 w-4 text-secondary-500" />
      default:
        return <Clock className="h-4 w-4 text-secondary-400" />
    }
  }

  const getInteractionColor = (type: string) => {
    switch (type) {
      case 'booking_created':
        return 'success'
      case 'booking_completed':
        return 'primary'
      case 'booking_cancelled':
        return 'error'
      case 'email_sent':
        return 'info'
      default:
        return 'secondary'
    }
  }

  if (isLoading) {
    return (
      <Card className={className}>
        <CardContent className="p-6">
          <div className="flex items-center justify-center">
            <LoadingSpinner size="md" />
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className={className}>
      <CardHeader title="Recent Interactions" />
      <CardContent>
        {!interactions || interactions.length === 0 ? (
          <EmptyState
            icon={<MessageSquare className="h-8 w-8" />}
            title="No interactions yet"
            description="Interactions will appear here as you communicate with this contact"
          />
        ) : (
          <div className="space-y-4">
            {interactions.map((interaction) => (
              <div
                key={interaction.id}
                className="flex items-start space-x-3 p-3 bg-secondary-50 rounded-lg"
              >
                <div className="flex-shrink-0 mt-1">
                  {getInteractionIcon(interaction.interaction_type)}
                </div>
                
                <div className="flex-1 min-w-0">
                  <div className="flex items-center space-x-2 mb-1">
                    <Badge
                      variant={getInteractionColor(interaction.interaction_type) as any}
                      size="sm"
                    >
                      {interaction.interaction_type_display}
                    </Badge>
                    <span className="text-xs text-secondary-500">
                      {formatRelativeTime(interaction.created_at)}
                    </span>
                  </div>
                  
                  <p className="text-sm text-secondary-900">
                    {interaction.description}
                  </p>
                  
                  {interaction.booking_id && (
                    <p className="text-xs text-secondary-500 mt-1">
                      Related to booking: {interaction.booking_id}
                    </p>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}