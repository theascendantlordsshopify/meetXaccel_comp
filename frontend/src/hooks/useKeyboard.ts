import { useEffect } from 'react'

export function useKeyboard(
  key: string | string[],
  handler: (event: KeyboardEvent) => void,
  options?: {
    target?: HTMLElement | Document
    preventDefault?: boolean
    stopPropagation?: boolean
  }
) {
  const { target = document, preventDefault = false, stopPropagation = false } = options || {}

  useEffect(() => {
    const handleKeyPress = (event: KeyboardEvent) => {
      const keys = Array.isArray(key) ? key : [key]
      
      if (keys.includes(event.key)) {
        if (preventDefault) event.preventDefault()
        if (stopPropagation) event.stopPropagation()
        handler(event)
      }
    }

    target.addEventListener('keydown', handleKeyPress)
    return () => target.removeEventListener('keydown', handleKeyPress)
  }, [key, handler, target, preventDefault, stopPropagation])
}

export function useEscapeKey(handler: () => void) {
  useKeyboard('Escape', handler)
}

export function useEnterKey(handler: () => void) {
  useKeyboard('Enter', handler)
}