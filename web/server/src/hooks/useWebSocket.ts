import { useEffect, useRef, useCallback, useState } from 'react'
import type { WSEvent } from '../api/types'

type MessageHandler = (event: WSEvent) => void

interface UseWebSocketOptions {
  onMessage?: MessageHandler
  reconnectDelay?: number
  enabled?: boolean
}

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const { onMessage, reconnectDelay = 3000, enabled = true } = options
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout>>()
  const [isConnected, setIsConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState<WSEvent | null>(null)

  const connect = useCallback(() => {
    if (!enabled) return

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${protocol}//${window.location.host}/api/v1/ws`

    try {
      const ws = new WebSocket(wsUrl)

      ws.onopen = () => {
        console.log('WebSocket connected')
        setIsConnected(true)
      }

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data) as WSEvent
          setLastMessage(data)
          onMessage?.(data)
        } catch (err) {
          console.error('WebSocket parse error:', err)
        }
      }

      ws.onerror = (error) => {
        console.error('WebSocket error:', error)
      }

      ws.onclose = () => {
        console.log('WebSocket disconnected')
        setIsConnected(false)
        wsRef.current = null

        // Attempt to reconnect
        reconnectTimeoutRef.current = setTimeout(connect, reconnectDelay)
      }

      wsRef.current = ws
    } catch (err) {
      console.error('WebSocket connection failed:', err)
      reconnectTimeoutRef.current = setTimeout(connect, reconnectDelay)
    }
  }, [enabled, onMessage, reconnectDelay])

  useEffect(() => {
    connect()

    return () => {
      clearTimeout(reconnectTimeoutRef.current)
      if (wsRef.current) {
        wsRef.current.close()
        wsRef.current = null
      }
    }
  }, [connect])

  const send = useCallback((data: unknown) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data))
    }
  }, [])

  return {
    isConnected,
    lastMessage,
    send,
  }
}
