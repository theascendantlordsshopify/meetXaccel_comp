import { useEffect, useRef } from 'react'

export function useTimeout(callback: () => void, delay: number | null) {
  const savedCallback = useRef<() => void>()

  // Remember the latest callback
  useEffect(() => {
    savedCallback.current = callback
  }, [callback])

  // Set up the timeout
  useEffect(() => {
    function tick() {
      savedCallback.current?.()
    }
    
    if (delay !== null) {
      const id = setTimeout(tick, delay)
      return () => clearTimeout(id)
    }
  }, [delay])
}