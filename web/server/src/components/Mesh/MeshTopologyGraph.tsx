import { useEffect, useRef, useCallback, useState } from 'react'
import type { MeshPeerInfo, MeshPeerStatus } from '../../api/types'

interface ExtendedPeer extends MeshPeerInfo {
  status?: MeshPeerStatus
  latency?: number
}

interface MeshTopologyGraphProps {
  peers: MeshPeerInfo[]
  selectedPeerId?: string
  onSelectPeer: (peer: MeshPeerInfo) => void
}

interface NodePosition {
  x: number
  y: number
  vx: number
  vy: number
  peer: MeshPeerInfo
}

function getStatusColor(status: MeshPeerStatus | undefined): string {
  switch (status) {
    case 'connected':
      return '#22c55e' // green-500
    case 'relayed':
      return '#06b6d4' // cyan-500
    case 'connecting':
      return '#f59e0b' // amber-500
    case 'discovered':
      return '#6366f1' // indigo-500
    case 'unreachable':
    case 'offline':
      return '#ef4444' // red-500
    default:
      return '#6b7280' // gray-500
  }
}

export function MeshTopologyGraph({
  peers,
  selectedPeerId,
  onSelectPeer,
}: MeshTopologyGraphProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const nodesRef = useRef<NodePosition[]>([])
  const animationRef = useRef<number | null>(null)
  const [hoveredNode, setHoveredNode] = useState<string | null>(null)
  const isDraggingRef = useRef(false)
  const draggedNodeRef = useRef<NodePosition | null>(null)

  // Initialize node positions
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const width = canvas.width
    const height = canvas.height
    const centerX = width / 2
    const centerY = height / 2
    const radius = Math.min(width, height) * 0.35

    // Create new nodes or update existing ones
    const newNodes: NodePosition[] = peers.map((peer, i) => {
      const existingNode = nodesRef.current.find((n) => n.peer.id === peer.id)
      if (existingNode) {
        existingNode.peer = peer
        return existingNode
      }

      // Place new nodes in a circle
      const angle = (2 * Math.PI * i) / Math.max(peers.length, 1)
      return {
        x: centerX + radius * Math.cos(angle),
        y: centerY + radius * Math.sin(angle),
        vx: 0,
        vy: 0,
        peer,
      }
    })

    nodesRef.current = newNodes
  }, [peers])

  // Force-directed layout simulation
  const simulate = useCallback(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const nodes = nodesRef.current
    const width = canvas.width
    const height = canvas.height
    const centerX = width / 2
    const centerY = height / 2

    // Apply forces
    for (let i = 0; i < nodes.length; i++) {
      const node = nodes[i]
      if (draggedNodeRef.current === node) continue

      // Center gravity
      const dx = centerX - node.x
      const dy = centerY - node.y
      node.vx += dx * 0.001
      node.vy += dy * 0.001

      // Repulsion from other nodes
      for (let j = 0; j < nodes.length; j++) {
        if (i === j) continue
        const other = nodes[j]
        const ddx = node.x - other.x
        const ddy = node.y - other.y
        const dist = Math.sqrt(ddx * ddx + ddy * ddy) || 1
        const force = 2000 / (dist * dist)
        node.vx += (ddx / dist) * force
        node.vy += (ddy / dist) * force
      }

      // Spring attraction to connected nodes (all nodes attract each other slightly)
      for (let j = 0; j < nodes.length; j++) {
        if (i === j) continue
        const other = nodes[j]
        const ddx = other.x - node.x
        const ddy = other.y - node.y
        const dist = Math.sqrt(ddx * ddx + ddy * ddy) || 1
        const idealDist = 150
        const force = (dist - idealDist) * 0.005
        node.vx += (ddx / dist) * force
        node.vy += (ddy / dist) * force
      }

      // Apply velocity with damping
      node.x += node.vx
      node.y += node.vy
      node.vx *= 0.9
      node.vy *= 0.9

      // Keep nodes within bounds
      const padding = 40
      node.x = Math.max(padding, Math.min(width - padding, node.x))
      node.y = Math.max(padding, Math.min(height - padding, node.y))
    }
  }, [])

  // Draw the graph
  const draw = useCallback(() => {
    const canvas = canvasRef.current
    const ctx = canvas?.getContext('2d')
    if (!canvas || !ctx) return

    const nodes = nodesRef.current
    const dpr = window.devicePixelRatio || 1

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height)

    // Draw connections (mesh - every node connected to every other)
    ctx.strokeStyle = 'rgba(107, 114, 128, 0.2)'
    ctx.lineWidth = 1
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        ctx.beginPath()
        ctx.moveTo(nodes[i].x, nodes[i].y)
        ctx.lineTo(nodes[j].x, nodes[j].y)
        ctx.stroke()
      }
    }

    // Draw highlighted connections for selected node
    if (selectedPeerId) {
      const selectedNode = nodes.find((n) => n.peer.id === selectedPeerId)
      if (selectedNode) {
        ctx.strokeStyle = 'rgba(168, 85, 247, 0.5)'
        ctx.lineWidth = 2
        for (const node of nodes) {
          if (node.peer.id !== selectedPeerId) {
            ctx.beginPath()
            ctx.moveTo(selectedNode.x, selectedNode.y)
            ctx.lineTo(node.x, node.y)
            ctx.stroke()
          }
        }
      }
    }

    // Draw nodes
    for (const node of nodes) {
      const extPeer = node.peer as ExtendedPeer
      const isSelected = node.peer.id === selectedPeerId
      const isHovered = node.peer.id === hoveredNode
      const nodeRadius = isSelected || isHovered ? 24 : 20

      // Node glow
      if (isSelected || isHovered) {
        const gradient = ctx.createRadialGradient(
          node.x,
          node.y,
          nodeRadius,
          node.x,
          node.y,
          nodeRadius * 2
        )
        gradient.addColorStop(0, 'rgba(168, 85, 247, 0.3)')
        gradient.addColorStop(1, 'rgba(168, 85, 247, 0)')
        ctx.fillStyle = gradient
        ctx.beginPath()
        ctx.arc(node.x, node.y, nodeRadius * 2, 0, Math.PI * 2)
        ctx.fill()
      }

      // Node circle
      const statusColor = getStatusColor(extPeer.status)
      ctx.fillStyle = isSelected ? '#a855f7' : statusColor
      ctx.beginPath()
      ctx.arc(node.x, node.y, nodeRadius, 0, Math.PI * 2)
      ctx.fill()

      // Node border
      ctx.strokeStyle = isSelected ? '#c084fc' : 'rgba(255, 255, 255, 0.2)'
      ctx.lineWidth = 2
      ctx.stroke()

      // Node label
      ctx.fillStyle = '#ffffff'
      ctx.font = `bold ${12 * dpr}px system-ui`
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      ctx.fillText(
        (node.peer.name || node.peer.id).charAt(0).toUpperCase(),
        node.x,
        node.y
      )

      // Name label below
      ctx.fillStyle = 'rgba(255, 255, 255, 0.7)'
      ctx.font = `${10 * dpr}px system-ui`
      ctx.fillText(
        node.peer.name || node.peer.id.slice(0, 8),
        node.x,
        node.y + nodeRadius + 12
      )
    }
  }, [selectedPeerId, hoveredNode])

  // Animation loop
  useEffect(() => {
    const animate = () => {
      simulate()
      draw()
      animationRef.current = requestAnimationFrame(animate)
    }

    animate()

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current)
      }
    }
  }, [simulate, draw])

  // Handle canvas resize
  useEffect(() => {
    const container = containerRef.current
    const canvas = canvasRef.current
    if (!container || !canvas) return

    const resizeObserver = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect
        const dpr = window.devicePixelRatio || 1
        canvas.width = width * dpr
        canvas.height = height * dpr
        canvas.style.width = `${width}px`
        canvas.style.height = `${height}px`

        const ctx = canvas.getContext('2d')
        if (ctx) {
          ctx.scale(dpr, dpr)
        }
      }
    })

    resizeObserver.observe(container)
    return () => resizeObserver.disconnect()
  }, [])

  // Handle mouse interactions
  const getNodeAtPosition = useCallback((x: number, y: number): NodePosition | null => {
    const nodes = nodesRef.current
    for (const node of nodes) {
      const dx = x - node.x
      const dy = y - node.y
      if (dx * dx + dy * dy < 30 * 30) {
        return node
      }
    }
    return null
  }, [])

  const handleMouseMove = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      const canvas = canvasRef.current
      if (!canvas) return

      const rect = canvas.getBoundingClientRect()
      const x = e.clientX - rect.left
      const y = e.clientY - rect.top

      if (isDraggingRef.current && draggedNodeRef.current) {
        draggedNodeRef.current.x = x
        draggedNodeRef.current.y = y
        draggedNodeRef.current.vx = 0
        draggedNodeRef.current.vy = 0
        return
      }

      const node = getNodeAtPosition(x, y)
      setHoveredNode(node?.peer.id || null)
      canvas.style.cursor = node ? 'pointer' : 'default'
    },
    [getNodeAtPosition]
  )

  const handleMouseDown = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      const canvas = canvasRef.current
      if (!canvas) return

      const rect = canvas.getBoundingClientRect()
      const x = e.clientX - rect.left
      const y = e.clientY - rect.top

      const node = getNodeAtPosition(x, y)
      if (node) {
        isDraggingRef.current = true
        draggedNodeRef.current = node
      }
    },
    [getNodeAtPosition]
  )

  const handleMouseUp = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      if (isDraggingRef.current && draggedNodeRef.current) {
        // Check if it was just a click (minimal movement)
        const canvas = canvasRef.current
        if (canvas) {
          const rect = canvas.getBoundingClientRect()
          const x = e.clientX - rect.left
          const y = e.clientY - rect.top
          const dx = x - draggedNodeRef.current.x
          const dy = y - draggedNodeRef.current.y
          if (dx * dx + dy * dy < 25) {
            onSelectPeer(draggedNodeRef.current.peer)
          }
        }
      }
      isDraggingRef.current = false
      draggedNodeRef.current = null
    },
    [onSelectPeer]
  )

  const handleClick = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      if (isDraggingRef.current) return

      const canvas = canvasRef.current
      if (!canvas) return

      const rect = canvas.getBoundingClientRect()
      const x = e.clientX - rect.left
      const y = e.clientY - rect.top

      const node = getNodeAtPosition(x, y)
      if (node) {
        onSelectPeer(node.peer)
      }
    },
    [getNodeAtPosition, onSelectPeer]
  )

  if (peers.length === 0) {
    return (
      <div className="h-full flex items-center justify-center text-bifrost-muted">
        <div className="text-center">
          <svg
            className="w-16 h-16 mx-auto mb-4 opacity-50"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={1}
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418"
            />
          </svg>
          <p>No peers to visualize</p>
        </div>
      </div>
    )
  }

  return (
    <div ref={containerRef} className="h-full w-full min-h-[300px]">
      <canvas
        ref={canvasRef}
        className="w-full h-full"
        onMouseMove={handleMouseMove}
        onMouseDown={handleMouseDown}
        onMouseUp={handleMouseUp}
        onMouseLeave={() => {
          setHoveredNode(null)
          isDraggingRef.current = false
          draggedNodeRef.current = null
        }}
        onClick={handleClick}
      />
    </div>
  )
}
