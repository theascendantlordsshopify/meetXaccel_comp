import React, { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, Calendar, Clock, Users, MapPin, Check, ChevronLeft, ChevronRight } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { LoadingSpinner } from '@/components/ui/LoadingSpinner'
import { Avatar } from '@/components/shared/Avatar'
import { BookingForm } from '@/features/events/components/BookingForm'
import { eventsService } from '@/services/events'
import { formatEventDuration, formatLocationType } from '@/utils/format'
import { formatDate, formatTime, getUserTimezone } from '@/utils/date'
import { cn } from '@/utils/cn'

export default function BookingPage() {
  const { organizerSlug, eventTypeSlug } = useParams<{ 
    organizerSlug: string
    eventTypeSlug: string 
  }>()
  const navigate = useNavigate()
  
  const [selectedDate, setSelectedDate] = useState<Date>(new Date())
  const [selectedSlot, setSelectedSlot] = useState<any>(null)
  const [currentWeek, setCurrentWeek] = useState(new Date())
  const [showBookingForm, setShowBookingForm] = useState(false)
  const [bookingSuccess, setBookingSuccess] = useState(false)
  const [createdBooking, setCreatedBooking] = useState<any>(null)

  const userTimezone = getUserTimezone()

  // Get event type data and available slots
  const { data: eventTypeData, isLoading, error } = useQuery({
    queryKey: ['publicEventType', organizerSlug, eventTypeSlug, selectedDate],
    queryFn: () => {
      const startDate = selectedDate.toISOString().split('T')[0]
      const endDate = selectedDate.toISOString().split('T')[0]
      
      return eventsService.getPublicEventTypePage(organizerSlug!, eventTypeSlug!, {
        start_date: startDate,
        end_date: endDate,
        timezone: userTimezone,
        attendee_count: 1,
      })
    },
    enabled: !!(organizerSlug && eventTypeSlug),
    staleTime: 5 * 60 * 1000, // 5 minutes
  })

  const handleSlotSelect = (slot: any) => {
    setSelectedSlot(slot)
    setShowBookingForm(true)
  }

  const handleBookingSuccess = (booking: any) => {
    setCreatedBooking(booking)
    setBookingSuccess(true)
  }

  const handleBackToSlots = () => {
    setShowBookingForm(false)
    setSelectedSlot(null)
  }

  const getWeekDates = (startDate: Date) => {
    const dates = []
    const start = new Date(startDate)
    start.setDate(start.getDate() - start.getDay()) // Start from Sunday
    
    for (let i = 0; i < 7; i++) {
      const date = new Date(start)
      date.setDate(start.getDate() + i)
      dates.push(date)
    }
    return dates
  }

  const navigateWeek = (direction: 'prev' | 'next') => {
    const newWeek = new Date(currentWeek)
    newWeek.setDate(newWeek.getDate() + (direction === 'next' ? 7 : -7))
    setCurrentWeek(newWeek)
    
    // Update selected date to first day of new week if current selection is not in new week
    const weekDates = getWeekDates(newWeek)
    if (!weekDates.some(date => date.toDateString() === selectedDate.toDateString())) {
      setSelectedDate(weekDates[1]) // Monday
    }
  }

  const weekDates = getWeekDates(currentWeek)
  const availableSlots = eventTypeData?.available_slots || []

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary-50 to-secondary-100">
        <div className="text-center">
          <LoadingSpinner size="lg" />
          <p className="mt-4 text-secondary-600">Loading booking page...</p>
        </div>
      </div>
    )
  }

  if (error || !eventTypeData) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary-50 to-secondary-100">
        <div className="text-center max-w-md">
          <div className="w-16 h-16 bg-error-100 rounded-full flex items-center justify-center mx-auto mb-4">
            <Calendar className="h-8 w-8 text-error-600" />
          </div>
          <h1 className="text-2xl font-bold text-secondary-900 mb-2">
            Event Type Not Found
          </h1>
          <p className="text-secondary-600 mb-6">
            The meeting type you're looking for doesn't exist or is not available.
          </p>
          <Button onClick={() => navigate(`/${organizerSlug}`)}>
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Organizer
          </Button>
        </div>
      </div>
    )
  }

  if (bookingSuccess) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary-50 to-secondary-100">
        <div className="max-w-md w-full">
          <Card className="text-center">
            <CardContent className="p-8">
              <div className="w-16 h-16 bg-success-100 rounded-full flex items-center justify-center mx-auto mb-6">
                <Check className="h-8 w-8 text-success-600" />
              </div>
              
              <h1 className="text-2xl font-bold text-secondary-900 mb-4">
                Booking Confirmed!
              </h1>
              
              <p className="text-secondary-600 mb-6">
                Your meeting with {eventTypeData.organizer_name} has been successfully scheduled.
              </p>
              
              {createdBooking && (
                <div className="bg-secondary-50 p-4 rounded-lg mb-6 text-left">
                  <h3 className="font-semibold text-secondary-900 mb-2">Meeting Details:</h3>
                  <div className="space-y-2 text-sm text-secondary-700">
                    <p><strong>Event:</strong> {eventTypeData.name}</p>
                    <p><strong>Date:</strong> {formatDate(createdBooking.start_time)}</p>
                    <p><strong>Time:</strong> {formatTime(createdBooking.start_time)}</p>
                    <p><strong>Duration:</strong> {eventTypeData.duration} minutes</p>
                    {createdBooking.meeting_link && (
                      <p><strong>Meeting Link:</strong> 
                        <a 
                          href={createdBooking.meeting_link} 
                          className="text-primary-600 hover:text-primary-700 ml-1"
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          Join Meeting
                        </a>
                      </p>
                    )}
                  </div>
                </div>
              )}
              
              <div className="space-y-3">
                {createdBooking?.management_url && (
                  <Button
                    variant="outline"
                    fullWidth
                    onClick={() => window.open(createdBooking.management_url, '_blank')}
                  >
                    Manage Booking
                  </Button>
                )}
                
                <Button
                  variant="ghost"
                  fullWidth
                  onClick={() => navigate(`/${organizerSlug}`)}
                >
                  Book Another Meeting
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    )
  }

  if (showBookingForm && selectedSlot) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-primary-50 to-secondary-100">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {/* Header */}
          <div className="mb-8">
            <Button
              variant="ghost"
              onClick={handleBackToSlots}
              className="mb-4"
            >
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Time Slots
            </Button>
            
            <div className="bg-white rounded-lg p-6 shadow-soft">
              <div className="flex items-center space-x-4">
                <Avatar name={eventTypeData.organizer_name} size="md" />
                <div>
                  <h1 className="text-2xl font-bold text-secondary-900">
                    {eventTypeData.name}
                  </h1>
                  <p className="text-secondary-600">
                    with {eventTypeData.organizer_name}
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Booking Form */}
          <BookingForm
            eventType={eventTypeData as any}
            selectedSlot={selectedSlot}
            onSuccess={handleBookingSuccess}
            onCancel={handleBackToSlots}
          />
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 to-secondary-100">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8">
          <Button
            variant="ghost"
            onClick={() => navigate(`/${organizerSlug}`)}
            className="mb-4"
          >
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to {eventTypeData.organizer_name}
          </Button>
          
          <div className="bg-white rounded-lg p-6 shadow-soft">
            <div className="flex items-start space-x-6">
              <Avatar name={eventTypeData.organizer_name} size="lg" />
              <div className="flex-1">
                <h1 className="text-3xl font-bold text-secondary-900 mb-2">
                  {eventTypeData.name}
                </h1>
                
                {eventTypeData.description && (
                  <p className="text-secondary-600 mb-4 leading-relaxed">
                    {eventTypeData.description}
                  </p>
                )}
                
                <div className="flex flex-wrap items-center gap-4 text-sm text-secondary-600">
                  <div className="flex items-center space-x-2">
                    <Clock className="h-4 w-4" />
                    <span>{formatEventDuration(eventTypeData.duration)}</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Users className="h-4 w-4" />
                    <span>
                      {eventTypeData.max_attendees === 1 
                        ? '1-on-1 meeting' 
                        : `Up to ${eventTypeData.max_attendees} people`
                      }
                    </span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <MapPin className="h-4 w-4" />
                    <span>{formatLocationType(eventTypeData.location_type)}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Calendar */}
          <div className="lg:col-span-1">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold text-secondary-900">
                    Select Date
                  </h3>
                  <div className="flex items-center space-x-2">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => navigateWeek('prev')}
                    >
                      <ChevronLeft className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => navigateWeek('next')}
                    >
                      <ChevronRight className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-7 gap-1 mb-2">
                  {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map((day) => (
                    <div key={day} className="text-center text-xs font-medium text-secondary-500 py-2">
                      {day}
                    </div>
                  ))}
                </div>
                
                <div className="grid grid-cols-7 gap-1">
                  {weekDates.map((date) => {
                    const isSelected = date.toDateString() === selectedDate.toDateString()
                    const isToday = date.toDateString() === new Date().toDateString()
                    const isPast = date < new Date() && !isToday
                    
                    return (
                      <button
                        key={date.toISOString()}
                        onClick={() => !isPast && setSelectedDate(date)}
                        disabled={isPast}
                        className={cn(
                          'aspect-square text-sm rounded-md transition-colors',
                          'hover:bg-primary-50 focus:outline-none focus:ring-2 focus:ring-primary-500',
                          isSelected && 'bg-primary-600 text-white',
                          isToday && !isSelected && 'ring-1 ring-primary-300',
                          isPast && 'opacity-50 cursor-not-allowed',
                          !isSelected && !isPast && 'text-secondary-900'
                        )}
                      >
                        {date.getDate()}
                      </button>
                    )
                  })}
                </div>
                
                <div className="mt-4 text-center">
                  <p className="text-sm text-secondary-600">
                    {formatDate(selectedDate, 'EEEE, MMMM dd, yyyy')}
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Time Slots */}
          <div className="lg:col-span-2">
            <Card>
              <CardHeader>
                <h3 className="text-lg font-semibold text-secondary-900">
                  Available Times
                </h3>
                <p className="text-sm text-secondary-600">
                  {formatDate(selectedDate, 'EEEE, MMMM dd')} • {userTimezone}
                </p>
              </CardHeader>
              <CardContent>
                {availableSlots.length === 0 ? (
                  <div className="text-center py-12">
                    <Clock className="h-12 w-12 text-secondary-400 mx-auto mb-4" />
                    <h3 className="text-lg font-semibold text-secondary-900 mb-2">
                      No Available Times
                    </h3>
                    <p className="text-secondary-600 mb-4">
                      There are no available time slots for this date.
                    </p>
                    <Button
                      variant="outline"
                      onClick={() => {
                        const tomorrow = new Date(selectedDate)
                        tomorrow.setDate(tomorrow.getDate() + 1)
                        setSelectedDate(tomorrow)
                      }}
                    >
                      Try Tomorrow
                    </Button>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {availableSlots.map((slot, index) => (
                      <Button
                        key={index}
                        variant="outline"
                        onClick={() => handleSlotSelect(slot)}
                        className="h-12 text-center hover:bg-primary-50 hover:border-primary-300 transition-colors"
                      >
                        {formatTime(slot.start_time)}
                      </Button>
                    ))}
                  </div>
                )}
                
                {availableSlots.length > 0 && (
                  <div className="mt-6 text-center">
                    <p className="text-xs text-secondary-500">
                      {availableSlots.length} time{availableSlots.length !== 1 ? 's' : ''} available
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Event Details */}
        <div className="mt-8">
          <Card>
            <CardHeader>
              <h3 className="text-lg font-semibold text-secondary-900">
                About this meeting
              </h3>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="flex items-center space-x-3">
                  <div className="p-2 bg-primary-100 rounded-lg">
                    <Clock className="h-5 w-5 text-primary-600" />
                  </div>
                  <div>
                    <p className="font-medium text-secondary-900">Duration</p>
                    <p className="text-sm text-secondary-600">
                      {formatEventDuration(eventTypeData.duration)}
                    </p>
                  </div>
                </div>

                <div className="flex items-center space-x-3">
                  <div className="p-2 bg-primary-100 rounded-lg">
                    <Users className="h-5 w-5 text-primary-600" />
                  </div>
                  <div>
                    <p className="font-medium text-secondary-900">Attendees</p>
                    <p className="text-sm text-secondary-600">
                      {eventTypeData.max_attendees === 1 
                        ? '1-on-1 meeting' 
                        : `Up to ${eventTypeData.max_attendees} people`
                      }
                    </p>
                  </div>
                </div>

                <div className="flex items-center space-x-3">
                  <div className="p-2 bg-primary-100 rounded-lg">
                    <MapPin className="h-5 w-5 text-primary-600" />
                  </div>
                  <div>
                    <p className="font-medium text-secondary-900">Location</p>
                    <p className="text-sm text-secondary-600">
                      {formatLocationType(eventTypeData.location_type)}
                    </p>
                  </div>
                </div>
              </div>

              {eventTypeData.location_details && (
                <div className="mt-6 p-4 bg-info-50 border border-info-200 rounded-lg">
                  <h4 className="font-medium text-info-800 mb-2">Location Details</h4>
                  <p className="text-sm text-info-700">
                    {eventTypeData.location_details}
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Organizer Info */}
        <div className="mt-8">
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center space-x-4">
                <Avatar name={eventTypeData.organizer_name} size="md" />
                <div className="flex-1">
                  <h4 className="font-semibold text-secondary-900">
                    {eventTypeData.organizer_name}
                  </h4>
                  {eventTypeData.organizer_bio && (
                    <p className="text-sm text-secondary-600 mt-1">
                      {eventTypeData.organizer_bio}
                    </p>
                  )}
                  {eventTypeData.organizer_company && (
                    <p className="text-xs text-secondary-500 mt-1">
                      {eventTypeData.organizer_company}
                    </p>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Footer */}
        <div className="mt-16 text-center">
          <p className="text-sm text-secondary-500">
            Powered by Calendly Clone
          </p>
        </div>
      </div>
    )
  )
}