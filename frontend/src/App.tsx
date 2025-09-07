import React from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ReactQueryDevtools } from '@tanstack/react-query-devtools'
import { Toaster } from 'react-hot-toast'
import { Layout } from '@/components/layout/Layout'
import { useAuth } from '@/hooks/useAuth'
import { ROUTES } from '@/constants/routes'
import { CACHE_DURATION, STALE_TIME, ENABLE_DEBUG } from '@/constants'

// Lazy load feature components
const Dashboard = React.lazy(() => import('@/features/dashboard/pages/Dashboard'))
const Login = React.lazy(() => import('@/features/auth/pages/Login'))
const Register = React.lazy(() => import('@/features/auth/pages/Register'))
const InvitationResponse = React.lazy(() => import('@/features/auth/pages/InvitationResponse'))
const EventTypes = React.lazy(() => import('@/features/events/pages/EventTypes'))
const Bookings = React.lazy(() => import('@/features/events/pages/Bookings'))
const Availability = React.lazy(() => import('@/features/availability/pages/Availability'))
const MFADeviceManagement = React.lazy(() => import('@/features/auth/pages/MFADeviceManagement'))
const SSOCallback = React.lazy(() => import('@/features/auth/pages/SSOCallback'))
const SSOSessionManagement = React.lazy(() => import('@/features/auth/pages/SSOSessionManagement'))
const Integrations = React.lazy(() => import('@/features/integrations/pages/Integrations'))
const CalendarIntegrations = React.lazy(() => import('@/features/integrations/pages/CalendarIntegrations'))
const VideoIntegrations = React.lazy(() => import('@/features/integrations/pages/VideoIntegrations'))
const WebhookIntegrations = React.lazy(() => import('@/features/integrations/pages/WebhookIntegrations'))
const Workflows = React.lazy(() => import('@/features/workflows/pages/Workflows'))
const CreateWorkflow = React.lazy(() => import('@/features/workflows/pages/CreateWorkflow'))
const EditWorkflow = React.lazy(() => import('@/features/workflows/pages/EditWorkflow'))
const WorkflowTemplates = React.lazy(() => import('@/features/workflows/pages/WorkflowTemplates'))
const Contacts = React.lazy(() => import('@/features/contacts/pages/Contacts'))
const ContactGroups = React.lazy(() => import('@/features/contacts/pages/ContactGroups'))
const ContactImport = React.lazy(() => import('@/features/contacts/pages/ContactImport'))
const Notifications = React.lazy(() => import('@/features/notifications/pages/Notifications'))
const NotificationTemplates = React.lazy(() => import('@/features/notifications/pages/NotificationTemplates'))
const NotificationLogs = React.lazy(() => import('@/features/notifications/pages/NotificationLogs'))
const NotificationPreferences = React.lazy(() => import('@/features/notifications/pages/NotificationPreferences'))

// Create a client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: STALE_TIME,
      gcTime: CACHE_DURATION,
      retry: (failureCount, error: any) => {
        // Don't retry on 4xx errors
        if (error?.status >= 400 && error?.status < 500) {
          return false
        }
        // Retry up to 3 times for other errors
        return failureCount < 3
      },
      retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 30000),
    },
    mutations: {
      retry: false,
    },
  },
})

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth()

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to={ROUTES.LOGIN} replace />
  }

  return <>{children}</>
}

function PublicRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth()

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  if (isAuthenticated) {
    return <Navigate to={ROUTES.DASHBOARD} replace />
  }

  return <>{children}</>
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Router>
        <div className="min-h-screen bg-secondary-50">
          <React.Suspense
            fallback={
              <div className="min-h-screen flex items-center justify-center">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
              </div>
            }
          >
            <Routes>
              {/* Public routes */}
              <Route
                path={ROUTES.LOGIN}
                element={
                  <PublicRoute>
                    <Login />
                  </PublicRoute>
                }
              />
              <Route
                path={ROUTES.REGISTER}
                element={
                  <PublicRoute>
                    <Register />
                  </PublicRoute>
                }
              />
              <Route
                path="/invitation"
                element={
                  <PublicRoute>
                    <InvitationResponse />
                  </PublicRoute>
                }
              />

              {/* SSO Callback routes */}
              <Route path="/saml/acs/" element={<SSOCallback />} />
              <Route path="/oidc/callback/" element={<SSOCallback />} />
              <Route path="/sso/callback/" element={<SSOCallback />} />

              {/* Protected routes */}
              <Route
                path="/"
                element={
                  <ProtectedRoute>
                    <Layout />
                  </ProtectedRoute>
                }
              >
                <Route index element={<Navigate to={ROUTES.DASHBOARD} replace />} />
                <Route path={ROUTES.DASHBOARD} element={<Dashboard />} />
                <Route path={ROUTES.EVENTS} element={<EventTypes />} />
                <Route path={ROUTES.BOOKINGS} element={<Bookings />} />
                <Route path={ROUTES.AVAILABILITY} element={<Availability />} />
                <Route path={ROUTES.SECURITY} element={<MFADeviceManagement />} />
                <Route path="/dashboard/security/sso" element={<SSOSessionManagement />} />
                <Route path={ROUTES.INTEGRATIONS} element={<Integrations />} />
                <Route path={ROUTES.INTEGRATIONS_CALENDAR} element={<CalendarIntegrations />} />
                <Route path={ROUTES.INTEGRATIONS_VIDEO} element={<VideoIntegrations />} />
                <Route path={ROUTES.INTEGRATIONS_WEBHOOKS} element={<WebhookIntegrations />} />
                <Route path={ROUTES.WORKFLOWS} element={<Workflows />} />
                <Route path={ROUTES.WORKFLOW_CREATE} element={<CreateWorkflow />} />
                <Route path={ROUTES.WORKFLOW_EDIT} element={<EditWorkflow />} />
                <Route path={ROUTES.WORKFLOW_TEMPLATES} element={<WorkflowTemplates />} />
                <Route path={ROUTES.CONTACTS} element={<Contacts />} />
                <Route path={ROUTES.CONTACT_GROUPS} element={<ContactGroups />} />
                <Route path={ROUTES.CONTACT_IMPORT} element={<ContactImport />} />
                <Route path={ROUTES.NOTIFICATIONS} element={<Notifications />} />
                <Route path={ROUTES.NOTIFICATION_TEMPLATES} element={<NotificationTemplates />} />
                <Route path={ROUTES.NOTIFICATION_LOGS} element={<NotificationLogs />} />
                <Route path={ROUTES.NOTIFICATION_PREFERENCES} element={<NotificationPreferences />} />
              </Route>

              {/* Catch all */}
              <Route path="*" element={<Navigate to={ROUTES.DASHBOARD} replace />} />
            </Routes>
          </React.Suspense>
        </div>

        <Toaster
          position="top-right"
          toastOptions={{
            duration: 5000,
            style: {
              background: '#fff',
              color: '#374151',
              border: '1px solid #e5e7eb',
              borderRadius: '0.75rem',
              boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
            },
            success: {
              iconTheme: {
                primary: '#10b981',
                secondary: '#fff',
              },
            },
            error: {
              iconTheme: {
                primary: '#ef4444',
                secondary: '#fff',
              },
            },
          }}
        />
      </Router>
      
      {ENABLE_DEBUG && <ReactQueryDevtools initialIsOpen={false} />}
    </QueryClientProvider>
  )
}

export default App