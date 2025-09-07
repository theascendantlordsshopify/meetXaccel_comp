import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { NotificationItem, Theme } from '@/types'

interface UIState {
  // Theme
  theme: Theme
  setTheme: (theme: Theme) => void

  // Sidebar
  sidebarCollapsed: boolean
  setSidebarCollapsed: (collapsed: boolean) => void
  toggleSidebar: () => void

  // Loading states
  globalLoading: boolean
  setGlobalLoading: (loading: boolean) => void

  // Notifications/Toasts
  notifications: NotificationItem[]
  addNotification: (notification: Omit<NotificationItem, 'id'>) => void
  removeNotification: (id: string) => void
  clearNotifications: () => void

  // Modals
  modals: Record<string, boolean>
  openModal: (modalId: string) => void
  closeModal: (modalId: string) => void
  toggleModal: (modalId: string) => void

  // Page state
  pageTitle: string
  setPageTitle: (title: string) => void

  // Search
  globalSearch: string
  setGlobalSearch: (search: string) => void

  // Filters
  activeFilters: Record<string, any>
  setFilter: (key: string, value: any) => void
  removeFilter: (key: string) => void
  clearFilters: () => void

  // View preferences
  viewPreferences: Record<string, any>
  setViewPreference: (key: string, value: any) => void

  // Command palette
  commandPaletteOpen: boolean
  setCommandPaletteOpen: (open: boolean) => void
}

export const uiStore = create<UIState>()(
  persist(
    (set, get) => ({
      // Initial state
      theme: 'light',
      sidebarCollapsed: false,
      globalLoading: false,
      notifications: [],
      modals: {},
      pageTitle: '',
      globalSearch: '',
      activeFilters: {},
      viewPreferences: {},
      commandPaletteOpen: false,

      // Theme actions
      setTheme: (theme: Theme) => {
        set({ theme })
        
        // Apply theme to document
        const root = document.documentElement
        root.classList.remove('light', 'dark')
        
        if (theme === 'system') {
          const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
          root.classList.add(systemTheme)
        } else {
          root.classList.add(theme)
        }
      },

      // Sidebar actions
      setSidebarCollapsed: (collapsed: boolean) => set({ sidebarCollapsed: collapsed }),
      toggleSidebar: () => set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),

      // Loading actions
      setGlobalLoading: (loading: boolean) => set({ globalLoading: loading }),

      // Notification actions
      addNotification: (notification) => {
        const id = Date.now().toString()
        const newNotification = { ...notification, id }
        
        set((state) => ({
          notifications: [...state.notifications, newNotification],
        }))

        // Auto-remove notification after duration
        if (notification.duration !== 0) {
          setTimeout(() => {
            get().removeNotification(id)
          }, notification.duration || 5000)
        }
      },

      removeNotification: (id: string) =>
        set((state) => ({
          notifications: state.notifications.filter((n) => n.id !== id),
        })),

      clearNotifications: () => set({ notifications: [] }),

      // Modal actions
      openModal: (modalId: string) =>
        set((state) => ({
          modals: { ...state.modals, [modalId]: true },
        })),

      closeModal: (modalId: string) =>
        set((state) => ({
          modals: { ...state.modals, [modalId]: false },
        })),

      toggleModal: (modalId: string) =>
        set((state) => ({
          modals: { ...state.modals, [modalId]: !state.modals[modalId] },
        })),

      // Page actions
      setPageTitle: (title: string) => {
        set({ pageTitle: title })
        document.title = title ? `${title} - Calendly Clone` : 'Calendly Clone'
      },

      // Search actions
      setGlobalSearch: (search: string) => set({ globalSearch: search }),

      // Filter actions
      setFilter: (key: string, value: any) =>
        set((state) => ({
          activeFilters: { ...state.activeFilters, [key]: value },
        })),

      removeFilter: (key: string) =>
        set((state) => {
          const { [key]: removed, ...rest } = state.activeFilters
          return { activeFilters: rest }
        }),

      clearFilters: () => set({ activeFilters: {} }),

      // View preference actions
      setViewPreference: (key: string, value: any) =>
        set((state) => ({
          viewPreferences: { ...state.viewPreferences, [key]: value },
        })),

      // Command palette actions
      setCommandPaletteOpen: (open: boolean) => set({ commandPaletteOpen: open }),
    }),
    {
      name: 'ui-storage',
      partialize: (state) => ({
        theme: state.theme,
        sidebarCollapsed: state.sidebarCollapsed,
        viewPreferences: state.viewPreferences,
      }),
    }
  )
)

// Helper hooks
export const useUI = () => {
  const {
    theme,
    setTheme,
    sidebarCollapsed,
    setSidebarCollapsed,
    toggleSidebar,
    globalLoading,
    setGlobalLoading,
    notifications,
    addNotification,
    removeNotification,
    clearNotifications,
    modals,
    openModal,
    closeModal,
    toggleModal,
    pageTitle,
    setPageTitle,
    globalSearch,
    setGlobalSearch,
    activeFilters,
    setFilter,
    removeFilter,
    clearFilters,
    viewPreferences,
    setViewPreference,
    commandPaletteOpen,
    setCommandPaletteOpen,
  } = uiStore()

  return {
    theme,
    setTheme,
    sidebarCollapsed,
    setSidebarCollapsed,
    toggleSidebar,
    globalLoading,
    setGlobalLoading,
    notifications,
    addNotification,
    removeNotification,
    clearNotifications,
    modals,
    openModal,
    closeModal,
    toggleModal,
    isModalOpen: (modalId: string) => modals[modalId] || false,
    pageTitle,
    setPageTitle,
    globalSearch,
    setGlobalSearch,
    activeFilters,
    setFilter,
    removeFilter,
    clearFilters,
    hasActiveFilters: Object.keys(activeFilters).length > 0,
    viewPreferences,
    setViewPreference,
    commandPaletteOpen,
    setCommandPaletteOpen,
    // Utility methods
    showSuccess: (title: string, message?: string) =>
      addNotification({ type: 'success', title, message }),
    showError: (title: string, message?: string) =>
      addNotification({ type: 'error', title, message }),
    showWarning: (title: string, message?: string) =>
      addNotification({ type: 'warning', title, message }),
    showInfo: (title: string, message?: string) =>
      addNotification({ type: 'info', title, message }),
  }
}

// Theme utilities
export const getSystemTheme = (): 'light' | 'dark' => {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

export const applyTheme = (theme: Theme) => {
  const root = document.documentElement
  root.classList.remove('light', 'dark')
  
  if (theme === 'system') {
    const systemTheme = getSystemTheme()
    root.classList.add(systemTheme)
  } else {
    root.classList.add(theme)
  }
}

// Initialize theme on app start
if (typeof window !== 'undefined') {
  const storedTheme = localStorage.getItem('ui-storage')
  if (storedTheme) {
    try {
      const parsed = JSON.parse(storedTheme)
      if (parsed.state?.theme) {
        applyTheme(parsed.state.theme)
      }
    } catch {
      // Ignore parsing errors
    }
  }

  // Listen for system theme changes
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    const currentTheme = uiStore.getState().theme
    if (currentTheme === 'system') {
      applyTheme('system')
    }
  })
}