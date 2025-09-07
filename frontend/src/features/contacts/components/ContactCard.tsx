import React from 'react'
import { Mail, Phone, Building, Calendar, Tag, MoreHorizontal, Edit, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Avatar } from '@/components/shared/Avatar'
import { formatRelativeTime } from '@/utils/date'
import { formatNumber } from '@/utils/helpers'
import type { Contact } from '@/types'

interface ContactCardProps {
  contact: Contact
  onEdit: (contact: Contact) => void
  onDelete: (contact: Contact) => void
  onViewDetails?: (contact: Contact) => void
  className?: string
}

export function ContactCard({ 
  contact, 
  onEdit, 
  onDelete, 
  onViewDetails,
  className 
}: ContactCardProps) {
  return (
    <Card className={`group hover:shadow-medium transition-all duration-200 ${className}`}>
      <CardHeader>
        <div className="flex items-start justify-between">
          <div className="flex items-center space-x-3">
            <Avatar name={contact.full_name} size="md" />
            <div className="flex-1 min-w-0">
              <h3 className="text-lg font-semibold text-secondary-900 group-hover:text-primary-900 transition-colors">
                {contact.full_name}
              </h3>
              <p className="text-sm text-secondary-600">
                {contact.email}
              </p>
              {contact.job_title && contact.company && (
                <p className="text-xs text-secondary-500">
                  {contact.job_title} at {contact.company}
                </p>
              )}
            </div>
          </div>
          <div className="flex items-center space-x-1">
            <Badge variant={contact.is_active ? 'success' : 'secondary'} size="sm">
              {contact.is_active ? 'Active' : 'Inactive'}
            </Badge>
            <div className="relative group/menu">
              <Button variant="ghost" size="sm">
                <MoreHorizontal className="h-4 w-4" />
              </Button>
              <div className="absolute right-0 top-full mt-1 w-48 bg-white rounded-lg shadow-strong border border-secondary-200 py-1 opacity-0 invisible group-hover/menu:opacity-100 group-hover/menu:visible transition-all duration-200 z-10">
                <button
                  onClick={() => onEdit(contact)}
                  className="w-full px-3 py-2 text-left text-sm text-secondary-700 hover:bg-secondary-50 flex items-center space-x-2"
                >
                  <Edit className="h-4 w-4" />
                  <span>Edit</span>
                </button>
                <button
                  onClick={() => window.open(`mailto:${contact.email}`, '_blank')}
                  className="w-full px-3 py-2 text-left text-sm text-secondary-700 hover:bg-secondary-50 flex items-center space-x-2"
                >
                  <Mail className="h-4 w-4" />
                  <span>Send Email</span>
                </button>
                {contact.phone && (
                  <button
                    onClick={() => window.open(`tel:${contact.phone}`, '_blank')}
                    className="w-full px-3 py-2 text-left text-sm text-secondary-700 hover:bg-secondary-50 flex items-center space-x-2"
                  >
                    <Phone className="h-4 w-4" />
                    <span>Call</span>
                  </button>
                )}
                <hr className="my-1 border-secondary-100" />
                <button
                  onClick={() => onDelete(contact)}
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
          {/* Contact Info */}
          <div className="grid grid-cols-1 gap-3">
            {contact.phone && (
              <div className="flex items-center space-x-2 text-sm text-secondary-600">
                <Phone className="h-4 w-4" />
                <span>{contact.phone}</span>
              </div>
            )}
            
            {contact.company && (
              <div className="flex items-center space-x-2 text-sm text-secondary-600">
                <Building className="h-4 w-4" />
                <span>{contact.company}</span>
              </div>
            )}
          </div>

          {/* Tags */}
          {contact.tags && contact.tags.length > 0 && (
            <div>
              <div className="flex flex-wrap gap-1">
                {contact.tags.slice(0, 3).map((tag, index) => (
                  <Badge key={index} variant="secondary" size="sm">
                    {tag}
                  </Badge>
                ))}
                {contact.tags.length > 3 && (
                  <Badge variant="secondary" size="sm">
                    +{contact.tags.length - 3} more
                  </Badge>
                )}
              </div>
            </div>
          )}

          {/* Booking Stats */}
          <div className="grid grid-cols-2 gap-4 pt-4 border-t border-secondary-100">
            <div className="text-center">
              <div className="flex items-center justify-center space-x-1">
                <Calendar className="h-4 w-4 text-secondary-400" />
                <span className="text-lg font-semibold text-secondary-900">
                  {formatNumber(contact.total_bookings)}
                </span>
              </div>
              <p className="text-xs text-secondary-500">Bookings</p>
            </div>
            <div className="text-center">
              <div className="flex items-center justify-center space-x-1">
                <Tag className="h-4 w-4 text-secondary-400" />
                <span className="text-lg font-semibold text-secondary-900">
                  {contact.groups_count}
                </span>
              </div>
              <p className="text-xs text-secondary-500">Groups</p>
            </div>
          </div>

          {/* Last Booking */}
          {contact.last_booking_date && (
            <div className="text-center">
              <p className="text-xs text-secondary-500">
                Last booking: {formatRelativeTime(contact.last_booking_date)}
              </p>
            </div>
          )}

          {/* Actions */}
          <div className="flex space-x-2 pt-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => window.open(`mailto:${contact.email}`, '_blank')}
              className="flex-1"
            >
              <Mail className="h-4 w-4 mr-2" />
              Email
            </Button>
            {onViewDetails && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => onViewDetails(contact)}
                className="flex-1"
              >
                View Details
              </Button>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}