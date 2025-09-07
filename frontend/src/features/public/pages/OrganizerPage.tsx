import React from 'react'
import { useParams, Link } from 'react-router-dom'
import { Calendar, Clock, Users, MapPin, ExternalLink, Globe, Building, Mail } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { Avatar } from '@/components/shared/Avatar'
import { eventsService } from '@/services/events'
import { formatEventDuration, formatLocationType } from '@/utils/format'
import { cn } from '@/utils/cn'

export default function OrganizerPage() {
  const { organizerSlug } = useParams<{ organizerSlug: string }>()

  const { data: organizerData, isLoading, error } = useQuery({
    queryKey: ['publicOrganizer', organizerSlug],
    queryFn: () => eventsService.getPublicOrganizerPage(organizerSlug!),
    enabled: !!organizerSlug,
    staleTime: 15 * 60 * 1000, // 15 minutes
  })

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary-50 to-secondary-100">
        <div className="text-center">
          <LoadingSpinner size="lg" />
          <p className="mt-4 text-secondary-600">Loading organizer profile...</p>
        </div>
      </div>
    )
  }

  if (error || !organizerData) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary-50 to-secondary-100">
        <div className="text-center max-w-md">
          <div className="w-16 h-16 bg-error-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <Calendar className="h-8 w-8 text-error-600" />
          </div>
          <h1 className="text-2xl font-bold text-secondary-900 mb-2">
            Organizer Not Found
          </h1>
          <p className="text-secondary-600 mb-6">
            The organizer you're looking for doesn't exist or is not available.
          </p>
          <Button onClick={() => window.location.href = '/'}>
            Go to Homepage
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 to-secondary-100">
      {/* Header */}
      <div className="bg-white border-b border-secondary-200">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="flex items-start space-x-6">
            <Avatar
              name={organizerData.display_name}
              size="xl"
              className="ring-4 ring-white shadow-medium"
            />
            <div className="flex-1 min-w-0">
              <h1 className="text-3xl font-bold text-secondary-900 mb-2">
                {organizerData.display_name}
              </h1>
              
              {organizerData.bio && (
                <p className="text-lg text-secondary-600 mb-4 leading-relaxed">
                  {organizerData.bio}
                </p>
              )}
              
              <div className="flex flex-wrap items-center gap-4 text-sm text-secondary-600">
                {organizerData.company && (
                  <div className="flex items-center space-x-2">
                    <Building className="h-4 w-4" />
                    <span>{organizerData.company}</span>
                  </div>
                )}
                
                <div className="flex items-center space-x-2">
                  <Globe className="h-4 w-4" />
                  <span>{organizerData.timezone}</span>
                </div>
                
                {organizerData.website && (
                  <a
                    href={organizerData.website}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center space-x-2 text-primary-600 hover:text-primary-700 transition-colors"
                  >
                    <ExternalLink className="h-4 w-4" />
                    <span>Website</span>
                  </a>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Event Types */}
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="text-center mb-12">
          <h2 className="text-2xl font-bold text-secondary-900 mb-4">
            Book a meeting with {organizerData.display_name.split(' ')[0]}
          </h2>
          <p className="text-secondary-600 max-w-2xl mx-auto">
            Choose from the available meeting types below to schedule your time together.
          </p>
        </div>

        {organizerData.event_types.length === 0 ? (
          <div className="text-center py-12">
            <Calendar className="h-16 w-16 text-secondary-400 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-secondary-900 mb-2">
              No Available Meeting Types
            </h3>
            <p className="text-secondary-600">
              This organizer hasn't set up any public meeting types yet.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {organizerData.event_types.map((eventType) => (
              <Card
                key={eventType.event_type_slug}
                className="group hover:shadow-strong transition-all duration-300 border-l-4 hover:scale-[1.02] cursor-pointer"
                style={{ borderLeftColor: organizerData.brand_color }}
                onClick={() => window.location.href = `/${organizerSlug}/${eventType.event_type_slug}`}
              >
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      <h3 className="text-xl font-semibold text-secondary-900 group-hover:text-primary-900 transition-colors mb-2">
                        {eventType.name}
                      </h3>
                      {eventType.description && (
                        <p className="text-secondary-600 line-clamp-2 mb-4">
                          {eventType.description}
                        </p>
                      )}
                    </div>
                    {eventType.is_group_event && (
                      <Badge variant="primary" size="sm">
                        Group Event
                      </Badge>
                    )}
                  </div>
                </CardHeader>

                <CardContent>
                  <div className="space-y-4">
                    {/* Event Details */}
                    <div className="grid grid-cols-2 gap-4">
                      <div className="flex items-center space-x-2 text-sm text-secondary-600">
                        <Clock className="h-4 w-4 text-primary-600" />
                        <span>{formatEventDuration(eventType.duration)}</span>
                      </div>
                      <div className="flex items-center space-x-2 text-sm text-secondary-600">
                        <Users className="h-4 w-4 text-primary-600" />
                        <span>
                          {eventType.max_attendees === 1 
                            ? '1-on-1' 
                            : `Up to ${eventType.max_attendees}`
                          }
                        </span>
                      </div>
                    </div>

                    {/* Location */}
                    <div className="flex items-center space-x-2 text-sm text-secondary-600">
                      <MapPin className="h-4 w-4 text-primary-600" />
                      <span>{formatLocationType(eventType.location_type)}</span>
                    </div>

                    {/* Book Button */}
                    <Link 
                      to={`/${organizerSlug}/${eventType.event_type_slug}`}
                      className="block"
                    >
                      <Button 
                        fullWidth 
                        className="mt-4 group-hover:shadow-md transition-shadow"
                        style={{ backgroundColor: organizerData.brand_color }}
                      >
                        Book Meeting
                      </Button>
                    </Link>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="bg-white border-t border-secondary-200 mt-16">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center text-sm text-secondary-500">
            <p>Powered by Calendly Clone</p>
          </div>
        </div>
      </div>
    </div>
  )
}