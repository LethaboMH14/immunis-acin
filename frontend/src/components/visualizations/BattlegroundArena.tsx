// frontend/src/components/visualizations/BattlegroundArena.tsx
// Cinematic Red vs Blue battle arena — the adversarial coevolution made visible
// WHY: This is the most dramatic demo moment. Red attacks fly across the screen,
// Blue shields block them. Judges see the arms race happening in real time.

import React, { useRef, useEffect, useCallback } from 'react';
import { Card } from '../common/Card';

// ─── Types ────────────────────────────────────────────────────────────────────

interface BattlegroundArenaProps {
  redWins: number;
  blueWins: number;
  isActive: boolean;
  currentRound?: number;
  totalRounds?: number;
  className?: string;
}

interface Projectile {
  x: number;
  y: number;
  vx: number;
  vy: number;
  type: 'attack' | 'block';
  life: number;
  maxLife: number;
  size: number;
}

interface Impact {
  x: number;
  y: number;
  life: number;
  maxLife: number;
  type: 'blocked' | 'hit';
  particles: { vx: number; vy: number; life: number }[];
}

// ─── Colors ───────────────────────────────────────────────────────────────────

const RED = { core: '#FF4D6A', glow: 'rgba(255,77,106,0.3)', dim: 'rgba(255,77,106,0.1)' };
const BLUE = { core: '#00E5A0', glow: 'rgba(0,229,160,0.3)', dim: 'rgba(0,229,160,0.1)' };

// ─── Component ────────────────────────────────────────────────────────────────

export function BattlegroundArena({
  redWins,
  blueWins,
  isActive,
  currentRound = 0,
  totalRounds = 0,
  className = '',
}: BattlegroundArenaProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);
  const projectilesRef = useRef<Projectile[]>([]);
  const impactsRef = useRef<Impact[]>([]);
  const timeRef = useRef(0);

  // Spawn projectiles
  useEffect(() => {
    if (!isActive) return;

    const interval = setInterval(() => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const h = canvas.offsetHeight;

      // Red attack
      projectilesRef.current.push({
        x: 60,
        y: h * 0.2 + Math.random() * h * 0.6,
        vx: 3 + Math.random() * 2,
        vy: (Math.random() - 0.5) * 1.5,
        type: 'attack',
        life: 1,
        maxLife: 1,
        size: 3 + Math.random() * 3,
      });

      if (projectilesRef.current.length > 40) {
        projectilesRef.current = projectilesRef.current.slice(-40);
      }
    }, 200);

    return () => clearInterval(interval);
  }, [isActive]);

  // Create impacts when projectiles reach the right side
  const createImpact = useCallback((x: number, y: number, blocked: boolean) => {
    const particles = Array.from({ length: 8 }, () => ({
      vx: (Math.random() - 0.5) * 4,
      vy: (Math.random() - 0.5) * 4,
      life: 1,
    }));

    impactsRef.current.push({
      x,
      y,
      life: 1,
      maxLife: 1,
      type: blocked ? 'blocked' : 'hit',
      particles,
    });

    if (impactsRef.current.length > 15) {
      impactsRef.current = impactsRef.current.slice(-15);
    }
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

    if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      ctx.scale(dpr, dpr);
    }

    timeRef.current += 0.016;
    const t = timeRef.current;

    // Clear with subtle gradient
    const bgGrad = ctx.createLinearGradient(0, 0, w, 0);
    bgGrad.addColorStop(0, 'rgba(30, 10, 15, 1)');
    bgGrad.addColorStop(0.5, '#0A0E1A');
    bgGrad.addColorStop(1, 'rgba(10, 20, 15, 1)');
    ctx.fillStyle = bgGrad;
    ctx.fillRect(0, 0, w, h);

    // Center divider line
    const midX = w / 2;
    ctx.beginPath();
    ctx.setLineDash([4, 8]);
    ctx.moveTo(midX, 0);
    ctx.lineTo(midX, h);
    ctx.strokeStyle = 'rgba(107, 114, 128, 0.3)';
    ctx.lineWidth = 1;
    ctx.stroke();
    ctx.setLineDash([]);

    // Red zone glow (left)
    const redGlow = ctx.createRadialGradient(30, h / 2, 0, 30, h / 2, 120);
    redGlow.addColorStop(0, 'rgba(255, 77, 106, 0.08)');
    redGlow.addColorStop(1, 'transparent');
    ctx.fillStyle = redGlow;
    ctx.fillRect(0, 0, midX, h);

    // Blue zone glow (right)
    const blueGlow = ctx.createRadialGradient(w - 30, h / 2, 0, w - 30, h / 2, 120);
    blueGlow.addColorStop(0, 'rgba(0, 229, 160, 0.08)');
    blueGlow.addColorStop(1, 'transparent');
    ctx.fillStyle = blueGlow;
    ctx.fillRect(midX, 0, midX, h);

    // Red agent icon (left)
    const redPulse = Math.sin(t * 3) * 0.15 + 0.85;
    ctx.beginPath();
    ctx.arc(40, h / 2, 18 * redPulse, 0, Math.PI * 2);
    ctx.fillStyle = RED.dim;
    ctx.fill();
    ctx.strokeStyle = RED.core;
    ctx.lineWidth = 2;
    ctx.stroke();
    ctx.fillStyle = RED.core;
    ctx.font = 'bold 14px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('R', 40, h / 2 + 5);

    // Blue agent icon (right)
    const bluePulse = Math.sin(t * 3 + 1) * 0.15 + 0.85;
    ctx.beginPath();
    ctx.arc(w - 40, h / 2, 18 * bluePulse, 0, Math.PI * 2);
    ctx.fillStyle = BLUE.dim;
    ctx.fill();
    ctx.strokeStyle = BLUE.core;
    ctx.lineWidth = 2;
    ctx.stroke();
    ctx.fillStyle = BLUE.core;
    ctx.fillText('B', w - 40, h / 2 + 5);

    // Blue shield wall
    const shieldX = w - 80;
    for (let y = 20; y < h - 20; y += 30) {
      const shimmer = Math.sin(t * 4 + y * 0.1) * 0.3 + 0.7;
      ctx.beginPath();
      ctx.moveTo(shieldX, y);
      ctx.lineTo(shieldX, y + 20);
      ctx.strokeStyle = `rgba(0, 229, 160, ${shimmer * 0.4})`;
      ctx.lineWidth = 3;
      ctx.stroke();
    }

    // Update and draw projectiles
    projectilesRef.current = projectilesRef.current.filter((p) => {
      p.x += p.vx;
      p.y += p.vy;
      p.life -= 0.008;

      if (p.x > shieldX - 5 && p.type === 'attack') {
        const blocked = Math.random() < (blueWins / Math.max(redWins + blueWins, 1));
        createImpact(p.x, p.y, blocked);
        return false;
      }

      if (p.life <= 0 || p.x > w || p.x < 0) return false;

      // Trail
      const trailGrad = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, p.size * 3);
      trailGrad.addColorStop(0, p.type === 'attack' ? RED.core : BLUE.core);
      trailGrad.addColorStop(1, 'transparent');
      ctx.fillStyle = trailGrad;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.size * 3, 0, Math.PI * 2);
      ctx.fill();

      // Core
      ctx.fillStyle = p.type === 'attack' ? RED.core : BLUE.core;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
      ctx.fill();

      return true;
    });

    // Update and draw impacts
    impactsRef.current = impactsRef.current.filter((impact) => {
      impact.life -= 0.03;
      if (impact.life <= 0) return false;

      const alpha = impact.life;
      const color = impact.type === 'blocked' ? BLUE.core : RED.core;

      // Shockwave ring
      const ringRadius = (1 - impact.life) * 30;
      ctx.beginPath();
      ctx.arc(impact.x, impact.y, ringRadius, 0, Math.PI * 2);
      ctx.strokeStyle = impact.type === 'blocked'
        ? `rgba(0, 229, 160, ${alpha * 0.5})` 
        : `rgba(255, 77, 106, ${alpha * 0.5})`;
      ctx.lineWidth = 2 * alpha;
      ctx.stroke();

      // Particles
      for (const particle of impact.particles) {
        particle.life -= 0.04;
        if (particle.life <= 0) continue;

        const px = impact.x + particle.vx * (1 - particle.life) * 15;
        const py = impact.y + particle.vy * (1 - particle.life) * 15;

        ctx.fillStyle = `${color}${Math.floor(particle.life * 255).toString(16).padStart(2, '0')}`;
        ctx.beginPath();
        ctx.arc(px, py, 1.5 * particle.life, 0, Math.PI * 2);
        ctx.fill();
      }

      return true;
    });

    // Score display
    ctx.fillStyle = RED.core;
    ctx.font = 'bold 28px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(String(redWins), midX - 50, 35);

    ctx.fillStyle = 'rgba(107, 114, 128, 0.5)';
    ctx.font = '14px Inter, sans-serif';
    ctx.fillText('vs', midX, 32);

    ctx.fillStyle = BLUE.core;
    ctx.font = 'bold 28px Inter, sans-serif';
    ctx.fillText(String(blueWins), midX + 50, 35);

    // Labels
    ctx.font = '10px Inter, sans-serif';
    ctx.fillStyle = 'rgba(209, 213, 219, 0.5)';
    ctx.fillText('RED AGENT', midX - 50, 50);
    ctx.fillText('BLUE AGENT', midX + 50, 50);

    // Round indicator
    if (isActive && currentRound > 0) {
      ctx.fillStyle = 'rgba(209, 213, 219, 0.4)';
      ctx.font = '10px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(`Round ${currentRound}${totalRounds ? ` / ${totalRounds}` : ''}`, midX, h - 12);
    }

    // Status
    if (!isActive) {
      ctx.fillStyle = 'rgba(107, 114, 128, 0.4)';
      ctx.font = '11px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('Awaiting battle...', midX, h - 12);
    }

    animRef.current = requestAnimationFrame(draw);
  }, [redWins, blueWins, isActive, currentRound, totalRounds, createImpact]);

  useEffect(() => {
    animRef.current = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(animRef.current);
  }, [draw]);

  return (
    <Card title="Adversarial Arena" padding="none" className={className}>
      <canvas
        ref={canvasRef}
        className="w-full cursor-default"
        style={{ width: '100%', height: 280 }}
      />
    </Card>
  );
}

export default BattlegroundArena;
