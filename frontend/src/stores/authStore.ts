import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { User, Profile } from '@/types'
import { authService, setAuthToken, removeAuthToken } from '@/services/auth'

interface AuthState {
  // State
  user: User | null
  token: string | null
  isAuthenticated: boolean
  isLoading: boolean
  error: string | null

  // Actions
  login: (email: string, password: string, rememberMe?: boolean) => Promise<void>
  register: (data: {
    email: string
    first_name: string
    last_name: string
    password: string
    password_confirm: string
    terms_accepted: boolean
  }) => Promise<void>
  logout: () => void
  setUser: (user: User, token: string) => void
  updateProfile: (data: Partial<Profile>) => Promise<void>
  refreshUser: () => Promise<void>
  clearError: () => void
  setLoading: (loading: boolean) => void
  setError: (error: string | null) => void
}

export const authStore = create<AuthState>()(
  persist(
    (set, get) => ({
      // Initial state
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,

      // Actions
      login: async (email: string, password: string, rememberMe = false) => {
        try {
          set({ isLoading: true, error: null })

          const response = await authService.login({
            email,
            password,
            remember_me: rememberMe,
          })

          get().setUser(response.user, response.token)
          set({ isLoading: false })
        } catch (error: any) {
          set({
            isLoading: false,
            error: error.message || 'Login failed',
          })
          throw error
        }
      },

      register: async (data) => {
        try {
          set({ isLoading: true, error: null })

          const response = await authService.register(data)
          get().setUser(response.user, response.token)
          set({ isLoading: false })
        } catch (error: any) {
          set({
            isLoading: false,
            error: error.message || 'Registration failed',
          })
          throw error
        }
      },

      logout: () => {
        // Call logout API (fire and forget)
        authService.logout().catch(() => {
          // Ignore errors on logout
        })

        // Remove auth token
        removeAuthToken()

        // Clear state
        set({
          user: null,
          token: null,
          isAuthenticated: false,
          isLoading: false,
          error: null,
        })
      },

      setUser: (user: User, token: string) => {
        // Set auth token for future requests
        setAuthToken(token)

        set({
          user,
          token,
          isAuthenticated: true,
          error: null,
        })
      },

      updateProfile: async (data) => {
        try {
          set({ isLoading: true, error: null })

          const updatedProfile = await authService.updateProfile(data)
          const currentUser = get().user

          if (currentUser) {
            set({
              user: {
                ...currentUser,
                profile: updatedProfile,
              },
              isLoading: false,
              error: null,
            })
          }
        } catch (error: any) {
          set({
            isLoading: false,
            error: error.message || 'Profile update failed',
          })
          throw error
        }
      },

      refreshUser: async () => {
        try {
          const profile = await authService.getProfile()
          const currentUser = get().user

          if (currentUser) {
            set({
              user: {
                ...currentUser,
                profile,
              },
            })
          }
        } catch (error: any) {
          // If refresh fails, user might need to re-authenticate
          if (error.status === 401) {
            get().logout()
          }
        }
      },

      clearError: () => set({ error: null }),
      setLoading: (loading: boolean) => set({ isLoading: loading }),
      setError: (error: string | null) => set({ error }),
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({
        user: state.user,
        token: state.token,
        isAuthenticated: state.isAuthenticated,
      }),
      onRehydrateStorage: () => (state) => {
        // Set auth token when rehydrating from storage
        if (state?.token) {
          setAuthToken(state.token)
        }
      },
    }
  )
)

// Helper hooks for easier access
export const useAuth = () => {
  const {
    user,
    token,
    isAuthenticated,
    isLoading,
    error,
    login,
    register,
    logout,
    updateProfile,
    refreshUser,
    clearError,
    setLoading,
    setError,
  } = authStore()

  return {
    user,
    token,
    isAuthenticated,
    isLoading,
    error,
    login,
    register,
    logout,
    updateProfile,
    refreshUser,
    clearError,
    setLoading,
    setError,
    setUser,
    // Computed values
    isOrganizer: user?.is_organizer || false,
    isEmailVerified: user?.is_email_verified || false,
    isMFAEnabled: user?.is_mfa_enabled || false,
    accountStatus: user?.account_status || 'unknown',
    organizerSlug: user?.profile?.organizer_slug || '',
    displayName: user?.profile?.display_name || user?.full_name || '',
    // Permission helpers
    hasRole: (roleName: string) => user?.roles?.some(role => role.name === roleName) || false,
    hasPermission: (permission: string) => 
      user?.roles?.some(role => 
        role.role_permissions?.some(perm => perm.codename === permission)
      ) || false,
  }
}