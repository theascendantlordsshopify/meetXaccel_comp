export const ROUTES = {
  // Authentication
  LOGIN: '/login',
  REGISTER: '/register',
  INVITATION_RESPONSE: '/invitation',
  FORGOT_PASSWORD: '/forgot-password',
  RESET_PASSWORD: '/reset-password',
  VERIFY_EMAIL: '/verify-email',
  
  // Dashboard
  DASHBOARD: '/dashboard',
  
  // Event Management
  EVENTS: '/dashboard/events',
  EVENT_CREATE: '/dashboard/events/create',
  EVENT_EDIT: '/dashboard/events/:id/edit',
  EVENT_QUESTIONS: '/dashboard/events/:id/questions',
  
  // Booking Management
  BOOKINGS: '/dashboard/bookings',
  BOOKING_DETAIL: '/dashboard/bookings/:id',
  BOOKING_ANALYTICS: '/dashboard/bookings/analytics',
  
  // Availability Management
  AVAILABILITY: '/dashboard/availability',
  AVAILABILITY_RULES: '/dashboard/availability/rules',
  AVAILABILITY_OVERRIDES: '/dashboard/availability/overrides',
  AVAILABILITY_BLOCKS: '/dashboard/availability/blocks',
  
  // Integrations
  INTEGRATIONS: '/dashboard/integrations',
  INTEGRATIONS_CALENDAR: '/dashboard/integrations/calendar',
  INTEGRATIONS_VIDEO: '/dashboard/integrations/video',
  INTEGRATIONS_WEBHOOKS: '/dashboard/integrations/webhooks',
  
  // Workflows
  WORKFLOWS: '/dashboard/workflows',
  WORKFLOW_CREATE: '/dashboard/workflows/create',
  WORKFLOW_EDIT: '/dashboard/workflows/:id/edit',
  WORKFLOW_TEMPLATES: '/dashboard/workflows/templates',
  
  // Notifications
  NOTIFICATIONS: '/dashboard/notifications',
  NOTIFICATION_TEMPLATES: '/dashboard/notifications/templates',
  NOTIFICATION_PREFERENCES: '/dashboard/notifications/preferences',
  NOTIFICATION_LOGS: '/dashboard/notifications/logs',
  
  // Contacts
  CONTACTS: '/dashboard/contacts',
  CONTACT_GROUPS: '/dashboard/contacts/groups',
  CONTACT_IMPORT: '/dashboard/contacts/import',
  
  // Settings & Profile
  SETTINGS: '/dashboard/settings',
  PROFILE: '/dashboard/profile',
  ACCOUNT: '/dashboard/account',
  SECURITY: '/dashboard/security',
  SSO_SESSIONS: '/dashboard/security/sso',
  BILLING: '/dashboard/billing',
  TEAM: '/dashboard/team',
  
  // Admin (for users with admin permissions)
  ADMIN: '/dashboard/admin',
  ADMIN_USERS: '/dashboard/admin/users',
  ADMIN_ROLES: '/dashboard/admin/roles',
  ADMIN_PERMISSIONS: '/dashboard/admin/permissions',
  ADMIN_SSO: '/dashboard/admin/sso',
  ADMIN_SYSTEM: '/dashboard/admin/system',
  
  // Public Routes
  HOME: '/',
  PUBLIC_ORGANIZER: '/:organizerSlug',
  PUBLIC_BOOKING: '/:organizerSlug/:eventTypeSlug',
  BOOKING_MANAGEMENT: '/booking/:accessToken/manage',
  
  // Legal & Support
  PRIVACY: '/privacy',
  TERMS: '/terms',
  SUPPORT: '/support',
  HELP: '/help',
} as const

// Route builders for dynamic routes
export const buildRoute = {
  eventEdit: (id: string) => `/dashboard/events/${id}/edit`,
  eventQuestions: (id: string) => `/dashboard/events/${id}/questions`,
  bookingDetail: (id: string) => `/dashboard/bookings/${id}`,
  workflowEdit: (id: string) => `/dashboard/workflows/${id}/edit`,
  publicOrganizer: (slug: string) => `/${slug}`,
  publicBooking: (organizerSlug: string, eventTypeSlug: string) => `/${organizerSlug}/${eventTypeSlug}`,
  bookingManagement: (accessToken: string) => `/booking/${accessToken}/manage`,
}

// Navigation structure for sidebar
export const NAVIGATION = [
  {
    name: 'Dashboard',
    href: ROUTES.DASHBOARD,
    icon: 'LayoutDashboard',
    description: 'Overview and quick actions',
  },
  {
    name: 'Event Types',
    href: ROUTES.EVENTS,
    icon: 'Calendar',
    description: 'Manage your meeting types',
    children: [
      { name: 'All Events', href: ROUTES.EVENTS },
      { name: 'Create Event', href: ROUTES.EVENT_CREATE },
    ],
  },
  {
    name: 'Bookings',
    href: ROUTES.BOOKINGS,
    icon: 'CalendarCheck',
    description: 'View and manage bookings',
    children: [
      { name: 'All Bookings', href: ROUTES.BOOKINGS },
      { name: 'Analytics', href: ROUTES.BOOKING_ANALYTICS },
    ],
  },
  {
    name: 'Availability',
    href: ROUTES.AVAILABILITY,
    icon: 'Clock',
    description: 'Set your available hours',
    children: [
      { name: 'Overview', href: ROUTES.AVAILABILITY },
      { name: 'Rules', href: ROUTES.AVAILABILITY_RULES },
      { name: 'Overrides', href: ROUTES.AVAILABILITY_OVERRIDES },
      { name: 'Blocked Times', href: ROUTES.AVAILABILITY_BLOCKS },
    ],
  },
  {
    name: 'Integrations',
    href: ROUTES.INTEGRATIONS,
    icon: 'Plug',
    description: 'Connect external services',
    children: [
      { name: 'Overview', href: ROUTES.INTEGRATIONS },
      { name: 'Calendar', href: ROUTES.INTEGRATIONS_CALENDAR },
      { name: 'Video', href: ROUTES.INTEGRATIONS_VIDEO },
      { name: 'Webhooks', href: ROUTES.INTEGRATIONS_WEBHOOKS },
    ],
  },
  {
    name: 'Workflows',
    href: ROUTES.WORKFLOWS,
    icon: 'Workflow',
    description: 'Automate your processes',
    children: [
      { name: 'All Workflows', href: ROUTES.WORKFLOWS },
      { name: 'Create Workflow', href: ROUTES.WORKFLOW_CREATE },
      { name: 'Templates', href: ROUTES.WORKFLOW_TEMPLATES },
    ],
  },
  {
    name: 'Notifications',
    href: ROUTES.NOTIFICATIONS,
    icon: 'Bell',
    description: 'Manage communications',
    children: [
      { name: 'Overview', href: ROUTES.NOTIFICATIONS },
      { name: 'Templates', href: ROUTES.NOTIFICATION_TEMPLATES },
      { name: 'Preferences', href: ROUTES.NOTIFICATION_PREFERENCES },
      { name: 'Logs', href: ROUTES.NOTIFICATION_LOGS },
    ],
  },
  {
    name: 'Contacts',
    href: ROUTES.CONTACTS,
    icon: 'Users',
    description: 'Manage your contacts',
    children: [
      { name: 'All Contacts', href: ROUTES.CONTACTS },
      { name: 'Groups', href: ROUTES.CONTACT_GROUPS },
      { name: 'Import', href: ROUTES.CONTACT_IMPORT },
    ],
  },
  {
    name: 'Settings',
    href: ROUTES.SETTINGS,
    icon: 'Settings',
    description: 'Account and preferences',
    children: [
      { name: 'Profile', href: ROUTES.PROFILE },
      { name: 'Account', href: ROUTES.ACCOUNT },
      { name: 'Security', href: ROUTES.SECURITY },
      { name: 'Team', href: ROUTES.TEAM },
    ],
  },
] as const

// Admin navigation (shown only to users with admin permissions)
export const ADMIN_NAVIGATION = [
  {
    name: 'Admin',
    href: ROUTES.ADMIN,
    icon: 'Shield',
    description: 'System administration',
    children: [
      { name: 'Users', href: ROUTES.ADMIN_USERS },
      { name: 'Roles & Permissions', href: ROUTES.ADMIN_ROLES },
      { name: 'SSO Configuration', href: ROUTES.ADMIN_SSO },
      { name: 'System Health', href: ROUTES.ADMIN_SYSTEM },
    ],
  },
] as const