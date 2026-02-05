import { useState, useEffect, useRef } from 'react'
import type { MeshPeerEvent } from '../../api/types'

interface MeshEventLogProps {
  networkId: string | null
}

function getEventTypeIcon(type: string) {
  switch (type) {
    case 'join':
      return (
        <div className="w-8 h-8 rounded-full bg-bifrost-success/10 flex items-center justify-center">
          <svg className="w-4 h-4 text-bifrost-success" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M18 7.5v3m0 0v3m0-3h3m-3 0h-3m-2.25-4.125a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zM3 19.235v-.11a6.375 6.375 0 0112.75 0v.109A12.318 12.318 0 019.374 21c-2.331 0-4.512-.645-6.374-1.766z" />
          </svg>
        </div>
      )
    case 'leave':
      return (
        <div className="w-8 h-8 rounded-full bg-bifrost-error/10 flex items-center justify-center">
          <svg className="w-4 h-4 text-bifrost-error" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M22 10.5h-6m-2.25-4.125a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zM4 19.235v-.11a6.375 6.375 0 0112.75 0v.109A12.318 12.318 0 0110.374 21c-2.331 0-4.512-.645-6.374-1.766z" />
          </svg>
        </div>
      )
    case 'update':
      return (
        <div className="w-8 h-8 rounded-full bg-bifrost-warning/10 flex items-center justify-center">
          <svg className="w-4 h-4 text-bifrost-warning" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" />
          </svg>
        </div>
      )
    default:
      return (
        <div className="w-8 h-8 rounded-full bg-bifrost-muted/10 flex items-center justify-center">
          <svg className="w-4 h-4 text-bifrost-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z" />
          </svg>
        </div>
      )
  }
}

function getEventMessage(event: MeshPeerEvent): string {
  const peerName = event.peer.name || event.peer.id
  switch (event.type) {
    case 'join':
      return `${peerName} joined the network`
    case 'leave':
      return `${peerName} left the network`
    case 'update':
      return `${peerName} updated their information`
    default:
      return `Unknown event for ${peerName}`
  }
}

function formatTimestamp(ts: string): string {
  try {
    const date = new Date(ts)
    const now = new Date()
    const diff = now.getTime() - date.getTime()

    if (diff < 60000) {
      return 'Just now'
    } else if (diff < 3600000) {
      const mins = Math.floor(diff / 60000)
      return `${mins}m ago`
    } else if (diff < 86400000) {
      const hours = Math.floor(diff / 3600000)
      return `${hours}h ago`
    } else {
      return date.toLocaleString()
    }
  } catch {
    return ts
  }
}

export function MeshEventLog({ networkId }: MeshEventLogProps) {
  const [events, setEvents] = useState<MeshPeerEvent[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!networkId) {
      setEvents([])
      return
    }

    // Connect to WebSocket for events
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${protocol}//${window.location.host}/api/v1/mesh/networks/${encodeURIComponent(networkId)}/events`

    try {
      const ws = new WebSocket(wsUrl)
      wsRef.current = ws

      ws.onopen = () => {
        setIsConnected(true)
      }

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data) as MeshPeerEvent
          setEvents((prev) => [data, ...prev].slice(0, 100)) // Keep last 100 events
        } catch (err) {
          console.error('Failed to parse WebSocket message:', err)
        }
      }

      ws.onerror = () => {
        setIsConnected(false)
      }

      ws.onclose = () => {
        setIsConnected(false)
      }

      return () => {
        ws.close()
        wsRef.current = null
      }
    } catch (err) {
      console.error('Failed to connect to WebSocket:', err)
    }
  }, [networkId])

  if (!networkId) {
    return (
      <div className="h-full flex items-center justify-center text-bifrost-muted">
        <div className="text-center">
          <svg
            className="w-12 h-12 mx-auto mb-3 opacity-50"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={1.5}
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M9 12h3.75M9 15h3.75M9 18h3.75m3 .75H18a2.25 2.25 0 002.25-2.25V6.108c0-1.135-.845-2.098-1.976-2.192a48.424 48.424 0 00-1.123-.08m-5.801 0c-.065.21-.1.433-.1.664 0 .414.336.75.75.75h4.5a.75.75 0 00.75-.75 2.25 2.25 0 00-.1-.664m-5.8 0A2.251 2.251 0 0113.5 2.25H15c1.012 0 1.867.668 2.15 1.586m-5.8 0c-.376.023-.75.05-1.124.08C9.095 4.01 8.25 4.973 8.25 6.108V8.25m0 0H4.875c-.621 0-1.125.504-1.125 1.125v11.25c0 .621.504 1.125 1.125 1.125h9.75c.621 0 1.125-.504 1.125-1.125V9.375c0-.621-.504-1.125-1.125-1.125H8.25zM6.75 12h.008v.008H6.75V12zm0 3h.008v.008H6.75V15zm0 3h.008v.008H6.75V18z"
            />
          </svg>
          <p>Select a network to view events</p>
        </div>
      </div>
    )
  }

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <h4 className="text-sm font-medium text-white">Event Log</h4>
        <div className="flex items-center gap-2">
          <span
            className={`w-2 h-2 rounded-full ${isConnected ? 'bg-bifrost-success' : 'bg-bifrost-error'}`}
          />
          <span className="text-xs text-bifrost-muted">
            {isConnected ? 'Live' : 'Disconnected'}
          </span>
        </div>
      </div>

      {/* Events */}
      <div className="flex-1 overflow-y-auto space-y-2">
        {events.length === 0 ? (
          <div className="text-center py-8 text-bifrost-muted">
            <p className="text-sm">No events yet</p>
            <p className="text-xs mt-1">Events will appear here as peers join, leave, or update</p>
          </div>
        ) : (
          events.map((event, i) => (
            <div
              key={`${event.timestamp}-${i}`}
              className="flex items-start gap-3 p-2 rounded bg-bifrost-bg/50 hover:bg-bifrost-bg transition-colors"
            >
              {getEventTypeIcon(event.type)}
              <div className="flex-1 min-w-0">
                <p className="text-sm text-white">{getEventMessage(event)}</p>
                {event.peer.virtual_ip && (
                  <p className="text-xs text-bifrost-muted font-mono">
                    IP: {event.peer.virtual_ip}
                  </p>
                )}
              </div>
              <span className="text-xs text-bifrost-muted flex-shrink-0">
                {formatTimestamp(event.timestamp)}
              </span>
            </div>
          ))
        )}
      </div>

      {/* Footer */}
      {events.length > 0 && (
        <div className="mt-2 pt-2 border-t border-bifrost-border">
          <button
            onClick={() => setEvents([])}
            className="text-xs text-bifrost-muted hover:text-white transition-colors"
          >
            Clear log
          </button>
        </div>
      )}
    </div>
  )
}
