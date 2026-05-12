// frontend/src/components/visualizations/MeshVisualization.tsx
// Cinematic mesh network — animated canvas with flowing antibody particles
// WHY: The mesh is the visual centrepiece of IMMUNIS. A static circle diagram
// doesn't communicate "living immune network". Flowing particles, pulsing nodes,
// and organic layout make judges feel the system is alive.

import React, { useRef, useEffect, useCallback, useState } from 'react';
import { Card } from '../common/Card';
import type { MeshNode } from '../../utils/types';

// ─── Types ────────────────────────────────────────────────────────────────────

interface MeshVisualizationProps {
  nodes: MeshNode[];
  className?: string;
}

interface VisNode {
  id: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  name: string;
  status: string;
  pulsePhase: number;
}

interface Particle {
  fromIdx: number;
  toIdx: number;
  progress: number;
  speed: number;
  color: string;
  size: number;
}

// ─── Colors ───────────────────────────────────────────────────────────────────

const COLORS = {
  nodeOnline: '#00E5A0',
  nodeOffline: '#FF4D6A',
  nodeSyncing: '#38BDF8',
  edge: 'rgba(56, 189, 248, 0.12)',
  edgeActive: 'rgba(0, 229, 160, 0.25)',
  particle: '#00E5A0',
  particleBroadcast: '#38BDF8',
  grid: 'rgba(55, 65, 81, 0.15)',
  glow: 'rgba(0, 229, 160, 0.3)',
  bg: '#0A0E1A',
  text: 'rgba(209, 213, 219, 0.7)',
};

// ─── Component ────────────────────────────────────────────────────────────────

export function MeshVisualization({ nodes, className = '' }: MeshVisualizationProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);
  const visNodesRef = useRef<VisNode[]>([]);
  const particlesRef = useRef<Particle[]>([]);
  const mouseRef = useRef({ x: -1, y: -1 });
  const [hoveredNode, setHoveredNode] = useState<VisNode | null>(null);
  const timeRef = useRef(0);

  // Initialize or update visual nodes
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const w = canvas.offsetWidth;
    const h = canvas.offsetHeight;
    const cx = w / 2;
    const cy = h / 2;

    // Create visual nodes from mesh nodes
    const existing = visNodesRef.current;
    const newVisNodes: VisNode[] = nodes.map((node, i) => {
      const existingNode = existing.find((n) => n.id === node.node_id);
      if (existingNode) {
        existingNode.status = node.status;
        (existingNode as any).label = node.hostname || node.city || `Node ${i + 1}`;
        return existingNode;
      }

      // Arrange in organic clusters
      const angle = (2 * Math.PI * i) / Math.max(nodes.length, 1) + Math.random() * 0.5;
      const dist = 80 + Math.random() * 60;
      return {
        id: node.node_id || `node-${i}`,
        x: cx + Math.cos(angle) * dist,
        y: cy + Math.sin(angle) * dist,
        vx: (Math.random() - 0.5) * 0.3,
        vy: (Math.random() - 0.5) * 0.3,
        radius: 8 + Math.random() * 4,
        name: node.hostname || node.city || `Node ${i + 1}`,
        status: node.status,
        pulsePhase: Math.random() * Math.PI * 2,
      };
    });

    // Add hub node at center if not present
    if (newVisNodes.length > 0 && !newVisNodes.find((n) => n.id === 'hub')) {
      newVisNodes.unshift({
        id: 'hub',
        x: cx,
        y: cy,
        vx: 0,
        vy: 0,
        radius: 14,
        name: 'IMMUNIS Hub',
        status: 'connected',
        pulsePhase: 0,
      });
    }

    visNodesRef.current = newVisNodes;
  }, [nodes]);

  // Spawn particles periodically
  useEffect(() => {
    const interval = setInterval(() => {
      const vn = visNodesRef.current;
      if (vn.length < 2) return;

      // Random broadcast particle
      const fromIdx = Math.floor(Math.random() * vn.length);
      let toIdx = Math.floor(Math.random() * vn.length);
      if (toIdx === fromIdx) toIdx = (toIdx + 1) % vn.length;

      particlesRef.current.push({
        fromIdx,
        toIdx,
        progress: 0,
        speed: 0.008 + Math.random() * 0.012,
        color: Math.random() > 0.5 ? COLORS.particle : COLORS.particleBroadcast,
        size: 2 + Math.random() * 2,
      });

      // Cap particles
      if (particlesRef.current.length > 30) {
        particlesRef.current = particlesRef.current.slice(-30);
      }
    }, 800);

    return () => clearInterval(interval);
  }, []);

  // Animation loop
  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    const w = canvas.offsetWidth;
    const h = canvas.offsetHeight;

    // Set canvas resolution
    if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      ctx.scale(dpr, dpr);
    }

    timeRef.current += 0.016;
    const t = timeRef.current;

    // Clear
    ctx.fillStyle = COLORS.bg;
    ctx.fillRect(0, 0, w, h);

    // Draw subtle grid
    ctx.strokeStyle = COLORS.grid;
    ctx.lineWidth = 0.5;
    const gridSize = 40;
    for (let x = 0; x < w; x += gridSize) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, h);
      ctx.stroke();
    }
    for (let y = 0; y < h; y += gridSize) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }

    const vn = visNodesRef.current;
    if (vn.length === 0) {
      // Empty state
      ctx.fillStyle = COLORS.text;
      ctx.font = '13px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('Mesh network inactive', w / 2, h / 2);
      animRef.current = requestAnimationFrame(draw);
      return;
    }

    // Gentle physics — nodes drift slightly
    for (const node of vn) {
      if (node.id === 'hub') continue;
      node.x += node.vx;
      node.y += node.vy;

      // Boundary bounce
      if (node.x < 30 || node.x > w - 30) node.vx *= -0.8;
      if (node.y < 30 || node.y > h - 30) node.vy *= -0.8;
      node.x = Math.max(30, Math.min(w - 30, node.x));
      node.y = Math.max(30, Math.min(h - 30, node.y));

      // Gentle random force
      node.vx += (Math.random() - 0.5) * 0.02;
      node.vy += (Math.random() - 0.5) * 0.02;

      // Damping
      node.vx *= 0.995;
      node.vy *= 0.995;

      // Attract toward center gently
      const dx = w / 2 - node.x;
      const dy = h / 2 - node.y;
      node.vx += dx * 0.00005;
      node.vy += dy * 0.00005;
    }

    // Draw edges
    for (let i = 0; i < vn.length; i++) {
      for (let j = i + 1; j < vn.length; j++) {
        const a = vn[i];
        const b = vn[j];
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < 200) {
          const alpha = 1 - dist / 200;
          const isHubEdge = a.id === 'hub' || b.id === 'hub';

          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.strokeStyle = isHubEdge
            ? `rgba(0, 229, 160, ${alpha * 0.2})` 
            : `rgba(56, 189, 248, ${alpha * 0.1})`;
          ctx.lineWidth = isHubEdge ? 1.5 : 0.8;
          ctx.stroke();
        }
      }
    }

    // Draw particles
    particlesRef.current = particlesRef.current.filter((p) => {
      p.progress += p.speed;
      if (p.progress >= 1) return false;

      const from = vn[p.fromIdx % vn.length];
      const to = vn[p.toIdx % vn.length];
      if (!from || !to) return false;

      const x = from.x + (to.x - from.x) * p.progress;
      const y = from.y + (to.y - from.y) * p.progress;

      // Glow
      const gradient = ctx.createRadialGradient(x, y, 0, x, y, p.size * 4);
      gradient.addColorStop(0, p.color);
      gradient.addColorStop(1, 'transparent');
      ctx.fillStyle = gradient;
      ctx.beginPath();
      ctx.arc(x, y, p.size * 4, 0, Math.PI * 2);
      ctx.fill();

      // Core
      ctx.fillStyle = p.color;
      ctx.beginPath();
      ctx.arc(x, y, p.size, 0, Math.PI * 2);
      ctx.fill();

      return true;
    });

    // Draw nodes
    for (const node of vn) {
      const isOnline = node.status === 'connected';
      const isHub = node.id === 'hub';
      const color = isOnline ? COLORS.nodeOnline : COLORS.nodeOffline;
      const pulse = Math.sin(t * 2 + node.pulsePhase) * 0.3 + 0.7;

      // Outer glow
      const glowRadius = node.radius * (2 + pulse * 0.5);
      const glow = ctx.createRadialGradient(node.x, node.y, node.radius * 0.5, node.x, node.y, glowRadius);
      glow.addColorStop(0, isHub ? 'rgba(0, 229, 160, 0.15)' : `${color}15`);
      glow.addColorStop(1, 'transparent');
      ctx.fillStyle = glow;
      ctx.beginPath();
      ctx.arc(node.x, node.y, glowRadius, 0, Math.PI * 2);
      ctx.fill();

      // Ring
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
      ctx.strokeStyle = `${color}${isHub ? '80' : '50'}`;
      ctx.lineWidth = isHub ? 2 : 1.5;
      ctx.stroke();

      // Fill
      ctx.fillStyle = `${color}${isHub ? '25' : '15'}`;
      ctx.fill();

      // Inner dot
      ctx.beginPath();
      ctx.arc(node.x, node.y, isHub ? 5 : 3, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();

      // Label
      ctx.fillStyle = COLORS.text;
      ctx.font = `${isHub ? '11' : '9'}px Inter, sans-serif`;
      ctx.textAlign = 'center';
      ctx.fillText(node.name, node.x, node.y + node.radius + 14);
    }

    // Check hover
    const mx = mouseRef.current.x;
    const my = mouseRef.current.y;
    let found: VisNode | null = null;
    for (const node of vn) {
      const dx = mx - node.x;
      const dy = my - node.y;
      if (dx * dx + dy * dy < node.radius * node.radius * 4) {
        found = node;
        break;
      }
    }
    if (found !== hoveredNode) {
      setHoveredNode(found);
    }

    animRef.current = requestAnimationFrame(draw);
  }, [hoveredNode]);

  // Start/stop animation
  useEffect(() => {
    animRef.current = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(animRef.current);
  }, [draw]);

  // Mouse tracking
  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;
    mouseRef.current = {
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    };
  }, []);

  const handleMouseLeave = useCallback(() => {
    mouseRef.current = { x: -1, y: -1 };
    setHoveredNode(null);
  }, []);

  return (
    <Card title="Mesh Network" padding="none" className={className}>
      <div className="relative" style={{ height: 380 }}>
        <canvas
          ref={canvasRef}
          className="w-full h-full cursor-crosshair"
          style={{ width: '100%', height: '100%' }}
          onMouseMove={handleMouseMove}
          onMouseLeave={handleMouseLeave}
        />

        {/* Hover tooltip */}
        {hoveredNode && (
          <div
            className="absolute z-10 px-3 py-2 rounded-lg pointer-events-none"
            style={{
              left: Math.min(mouseRef.current.x + 12, 280),
              top: mouseRef.current.y - 40,
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border-primary)',
              boxShadow: 'var(--shadow-lg)',
            }}
          >
            <p className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>
              {hoveredNode.name}
            </p>
            <p className="text-[10px]" style={{ color: hoveredNode.status === 'connected' ? COLORS.nodeOnline : COLORS.nodeOffline }}>
              {hoveredNode.status === 'connected' ? '● Online' : '● Offline'}
            </p>
          </div>
        )}

        {/* Legend */}
        <div className="absolute bottom-3 left-3 flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full" style={{ background: COLORS.nodeOnline }} />
            <span className="text-[9px]" style={{ color: COLORS.text }}>Online</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-full" style={{ background: COLORS.nodeOffline }} />
            <span className="text-[9px]" style={{ color: COLORS.text }}>Offline</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-1.5 h-1.5 rounded-full" style={{ background: COLORS.particleBroadcast }} />
            <span className="text-[9px]" style={{ color: COLORS.text }}>Broadcast</span>
          </div>
        </div>
      </div>
    </Card>
  );
}

export default MeshVisualization;
