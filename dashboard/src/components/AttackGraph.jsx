import React, { useEffect, useRef, useState } from 'react'

// Node types and their visual configs
const NODE_CONFIG = {
  target:     { color: '#00d4ff', icon: '◎', size: 44 },
  recon:      { color: '#bd93f9', icon: '⬡', size: 36 },
  vulnscan:   { color: '#ffd166', icon: '⚑', size: 36 },
  exploit:    { color: '#ff3b5c', icon: '⚡', size: 36 },
  finding:    { color: '#ff3b5c', icon: '🚨', size: 32 },
  tool:       { color: '#6b8299', icon: '🔧', size: 28 },
  approved:   { color: '#00ff9d', icon: '✓', size: 28 },
  rejected:   { color: '#ff3b5c', icon: '✕', size: 28 },
  ai:         { color: '#00d4ff', icon: '🧠', size: 32 },
}

function buildGraph(events, findings) {
  const nodes = []
  const edges = []
  const seen  = new Set()

  const addNode = (id, label, type, extra = {}) => {
    if (seen.has(id)) return
    seen.add(id)
    nodes.push({ id, label, type, ...extra })
  }

  // Root target node
  addNode('target', 'TARGET', 'target')

  // Group events by tool
  const toolEvents = {}
  events.forEach(ev => {
    if (!ev.tool || ev.tool === 'runner') return
    if (!toolEvents[ev.tool]) toolEvents[ev.tool] = []
    toolEvents[ev.tool].push(ev)
  })

  Object.entries(toolEvents).forEach(([tool, evs]) => {
    const phase    = evs[0]?.phase || 'recon'
    const toolId   = `tool_${tool}`
    const phaseId  = `phase_${phase}`
    const findings = evs.filter(e => e.level === 'finding').length

    addNode(phaseId, phase.toUpperCase(), phase)
    if (!edges.find(e => e.from === 'target' && e.to === phaseId)) {
      edges.push({ from: 'target', to: phaseId })
    }

    addNode(toolId, tool, 'tool', { findings })
    if (!edges.find(e => e.from === phaseId && e.to === toolId)) {
      edges.push({ from: phaseId, to: toolId })
    }
  })

  // Add findings as leaf nodes
  const sevColors = { critical: '#ff3b5c', high: '#ff8c42', medium: '#ffd166', low: '#00ff9d', info: '#6b8299' }
  findings.slice(0, 20).forEach((f, i) => {
    const fid = `finding_${f.id || i}`
    addNode(fid, f.title?.slice(0, 24) || 'Finding', 'finding', {
      severity: f.severity,
      sevColor: sevColors[f.severity] || '#6b8299',
      tool: f.tool,
    })
    const toolId = f.tool ? `tool_${f.tool}` : 'phase_vulnscan'
    if (seen.has(toolId)) {
      edges.push({ from: toolId, to: fid })
    }
  })

  return { nodes, edges }
}

// Simple force-directed layout
function layoutNodes(nodes, edges, w, h) {
  if (!nodes.length) return []

  const pos = {}
  const cx = w / 2, cy = h / 2

  nodes.forEach((n, i) => {
    if (n.id === 'target') {
      pos[n.id] = { x: cx, y: cy }
    } else if (n.type === 'recon' || n.type === 'vulnscan' || n.type === 'exploit') {
      const total = nodes.filter(x => ['recon','vulnscan','exploit'].includes(x.type)).length
      const idx   = nodes.filter(x => ['recon','vulnscan','exploit'].includes(x.type)).indexOf(n)
      const angle = (idx / Math.max(total, 1)) * Math.PI * 2 - Math.PI / 2
      pos[n.id] = { x: cx + Math.cos(angle) * 110, y: cy + Math.sin(angle) * 90 }
    } else if (n.type === 'tool') {
      const parentEdge = edges.find(e => e.to === n.id)
      const parent     = parentEdge ? pos[parentEdge.from] : { x: cx, y: cy }
      const toolNodes  = nodes.filter(x => x.type === 'tool')
      const idx        = toolNodes.indexOf(n)
      const angle      = (idx / Math.max(toolNodes.length, 1)) * Math.PI * 2
      pos[n.id] = {
        x: (parent?.x || cx) + Math.cos(angle) * 80,
        y: (parent?.y || cy) + Math.sin(angle) * 70,
      }
    } else if (n.type === 'finding') {
      const parentEdge = edges.find(e => e.to === n.id)
      const parent     = parentEdge ? pos[parentEdge.from] : { x: cx, y: cy }
      const findNodes  = nodes.filter(x => x.type === 'finding')
      const idx        = findNodes.indexOf(n)
      const angle      = (idx / Math.max(findNodes.length, 1)) * Math.PI * 2
      const r          = 60
      pos[n.id] = {
        x: Math.max(30, Math.min(w - 30, (parent?.x || cx) + Math.cos(angle) * r)),
        y: Math.max(30, Math.min(h - 30, (parent?.y || cy) + Math.sin(angle) * r)),
      }
    } else {
      pos[n.id] = { x: cx + (Math.random() - 0.5) * 200, y: cy + (Math.random() - 0.5) * 150 }
    }
  })

  return nodes.map(n => ({ ...n, ...pos[n.id] }))
}

export default function AttackGraph({ events = [], findings = [], scanStatus }) {
  const svgRef  = useRef(null)
  const [size, setSize] = useState({ w: 600, h: 380 })
  const [hovered, setHovered] = useState(null)

  useEffect(() => {
    const obs = new ResizeObserver(entries => {
      const { width, height } = entries[0].contentRect
      setSize({ w: width, h: height })
    })
    if (svgRef.current) obs.observe(svgRef.current.parentElement)
    return () => obs.disconnect()
  }, [])

  const { nodes: rawNodes, edges } = buildGraph(events, findings)
  const nodes = layoutNodes(rawNodes, edges, size.w, size.h)
  const posMap = Object.fromEntries(nodes.map(n => [n.id, n]))

  const isRunning = scanStatus === 'running'

  return (
    <div style={{
      width: '100%', height: '100%', position: 'relative',
      background: 'var(--bg-base)', overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0,
        padding: '8px 14px', zIndex: 2,
        display: 'flex', alignItems: 'center', gap: 8,
        background: 'linear-gradient(180deg, var(--bg-surface) 0%, transparent 100%)',
      }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--accent)', letterSpacing: 1 }}>
          ATTACK GRAPH
        </span>
        {isRunning && <span className="pulse-dot" />}
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>
          {nodes.length} nodes · {findings.length} findings
        </span>
      </div>

      <svg ref={svgRef} width="100%" height="100%" style={{ display: 'block' }}>
        <defs>
          <marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
            <path d="M0,0 L6,3 L0,6 Z" fill="var(--border-bright)" />
          </marker>
          <filter id="glow">
            <feGaussianBlur stdDeviation="2" result="coloredBlur" />
            <feMerge><feMergeNode in="coloredBlur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>

        {/* Edges */}
        {edges.map((edge, i) => {
          const from = posMap[edge.from]
          const to   = posMap[edge.to]
          if (!from || !to) return null
          return (
            <line
              key={i}
              x1={from.x} y1={from.y}
              x2={to.x}   y2={to.y}
              stroke="var(--border-bright)"
              strokeWidth={1}
              strokeDasharray="4,3"
              markerEnd="url(#arrow)"
              opacity={0.5}
            />
          )
        })}

        {/* Nodes */}
        {nodes.map(node => {
          const cfg     = NODE_CONFIG[node.type] || NODE_CONFIG.tool
          const color   = node.sevColor || cfg.color
          const r       = cfg.size / 2
          const isHov   = hovered === node.id
          const pulsing = isRunning && (node.type === 'ai' || node.id.includes('aggressive') || node.id.includes('passive'))

          return (
            <g
              key={node.id}
              transform={`translate(${node.x},${node.y})`}
              onMouseEnter={() => setHovered(node.id)}
              onMouseLeave={() => setHovered(null)}
              style={{ cursor: 'pointer' }}
            >
              {/* Glow ring on hover or pulse */}
              {(isHov || pulsing) && (
                <circle r={r + 6} fill="none" stroke={color} strokeWidth={1.5}
                  opacity={pulsing ? 0.4 : 0.6}
                  style={pulsing ? { animation: 'pulse 1.5s infinite' } : {}}
                />
              )}

              {/* Main circle */}
              <circle
                r={r}
                fill={`${color}22`}
                stroke={color}
                strokeWidth={isHov ? 2 : 1.5}
                filter={isHov ? 'url(#glow)' : 'none'}
              />

              {/* Icon */}
              <text
                textAnchor="middle"
                dominantBaseline="central"
                fontSize={r * 0.8}
                style={{ userSelect: 'none', pointerEvents: 'none' }}
              >
                {cfg.icon}
              </text>

              {/* Label */}
              <text
                y={r + 12}
                textAnchor="middle"
                fill={isHov ? color : 'var(--text-dim)'}
                fontSize={9}
                fontFamily="var(--font-mono)"
                style={{ userSelect: 'none', pointerEvents: 'none' }}
              >
                {node.label?.slice(0, 16)}
              </text>

              {/* Finding count badge */}
              {node.findings > 0 && (
                <g transform={`translate(${r - 4}, ${-r + 4})`}>
                  <circle r={8} fill="var(--red)" />
                  <text textAnchor="middle" dominantBaseline="central"
                    fill="#fff" fontSize={8} fontWeight="bold"
                    style={{ pointerEvents: 'none' }}>
                    {node.findings}
                  </text>
                </g>
              )}
            </g>
          )
        })}
      </svg>

      {/* Empty state */}
      {nodes.length <= 1 && (
        <div style={{
          position: 'absolute', inset: 0,
          display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center',
          gap: 8, pointerEvents: 'none',
        }}>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>
            Attack graph builds as scan progresses
          </div>
        </div>
      )}
    </div>
  )
}
