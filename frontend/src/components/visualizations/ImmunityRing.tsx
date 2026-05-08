// frontend/src/components/visualizations/ImmunityRing.tsx
// Premium immunity gauge — multi-ring animated canvas with particles
// WHY: The immunity score is the single most important number. The basic SVG
// gauge doesn't convey the weight of this metric. This version glows, pulses,
// and breathes — it looks alive because the system IS alive.

import React, { useRef, useEffect, useCallback, useState } from 'react';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ImmunityRingProps {
  score: number;
  antibodyCount?: number;
  threatsBlocked?: number;
  className?: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score >= 80) return '#00E5A0';
  if (score >= 60) return '#34D399';
  if (score >= 40) return '#FFAA33';
  if (score >= 20) return '#F97316';
  return '#FF4D6A';
}

function scoreLabel(score: number): string {
  if (score >= 80) return 'IMMUNE';
  if (score >= 60) return 'PROTECTED';
  if (score >= 40) return 'DEVELOPING';
  if (score >= 20) return 'VULNERABLE';
  return 'CRITICAL';
}

// ─── Component ────────────────────────────────────────────────────────────────

export function ImmunityRing({
  score,
  antibodyCount = 0,
  threatsBlocked = 0,
  className = '',
}: ImmunityRingProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number>(0);
  const timeRef = useRef(0);
  const displayScoreRef = useRef(0);
  const targetScoreRef = useRef(score);
  const particlesRef = useRef<{ angle: number; radius: number; speed: number; size: number; alpha: number }[]>([]);

  // Initialize particles
  useEffect(() => {
    particlesRef.current = Array.from({ length: 20 }, () => ({
      angle: Math.random() * Math.PI * 2,
      radius: 85 + Math.random() * 25,
      speed: 0.003 + Math.random() * 0.005,
      size: 0.5 + Math.random() * 1.5,
      alpha: 0.2 + Math.random() * 0.4,
    }));
  }, []);

  useEffect(() => {
    targetScoreRef.current = score;
  }, [score]);

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    const size = canvas.offsetWidth;
    const h = canvas.offsetHeight;

    if (canvas.width !== size * dpr || canvas.height !== h * dpr) {
      canvas.width = size * dpr;
      canvas.height = h * dpr;
      ctx.scale(dpr, dpr);
    }

    timeRef.current += 0.016;
    const t = timeRef.current;

    // Animate score
    const diff = targetScoreRef.current - displayScoreRef.current;
    displayScoreRef.current += diff * 0.05;
    const currentScore = displayScoreRef.current;
    const color = scoreColor(currentScore);

    const cx = size / 2;
    const cy = h / 2 - 10;

    // Clear
    ctx.clearRect(0, 0, size, h);

    // Ambient glow behind rings
    const ambientGlow = ctx.createRadialGradient(cx, cy, 30, cx, cy, 110);
    ambientGlow.addColorStop(0, `${color}10`);
    ambientGlow.addColorStop(1, 'transparent');
    ctx.fillStyle = ambientGlow;
    ctx.beginPath();
    ctx.arc(cx, cy, 110, 0, Math.PI * 2);
    ctx.fill();

    // ─── Outer ring (immunity score) ────────────────────────────────

    const outerR = 88;
    const outerWidth = 6;
    const startAngle = -Math.PI * 0.75;
    const totalArc = Math.PI * 1.5;
    const scoreArc = (currentScore / 100) * totalArc;

    // Track (background)
    ctx.beginPath();
    ctx.arc(cx, cy, outerR, startAngle, startAngle + totalArc);
    ctx.strokeStyle = 'rgba(55, 65, 81, 0.3)';
    ctx.lineWidth = outerWidth;
    ctx.lineCap = 'round';
    ctx.stroke();

    // Score arc
    if (scoreArc > 0) {
      const arcGrad = ctx.createConicGradient(startAngle, cx, cy);
      arcGrad.addColorStop(0, `${color}CC`);
      arcGrad.addColorStop(scoreArc / (Math.PI * 2), color);
      arcGrad.addColorStop(1, `${color}CC`);

      ctx.beginPath();
      ctx.arc(cx, cy, outerR, startAngle, startAngle + scoreArc);
      ctx.strokeStyle = color;
      ctx.lineWidth = outerWidth;
      ctx.lineCap = 'round';
      ctx.stroke();

      // Glow on the arc
      ctx.shadowColor = color;
      ctx.shadowBlur = 12;
      ctx.beginPath();
      ctx.arc(cx, cy, outerR, startAngle, startAngle + scoreArc);
      ctx.strokeStyle = `${color}60`;
      ctx.lineWidth = outerWidth + 4;
      ctx.stroke();
      ctx.shadowBlur = 0;

      // End dot
      const endX = cx + Math.cos(startAngle + scoreArc) * outerR;
      const endY = cy + Math.sin(startAngle + scoreArc) * outerR;
      ctx.beginPath();
      ctx.arc(endX, endY, 4, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.shadowColor = color;
      ctx.shadowBlur = 8;
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    // ─── Middle ring (antibody count indicator) ─────────────────────

    const midR = 72;
    const midWidth = 3;
    const antibodyPct = Math.min(antibodyCount / 20, 1);
    const antibodyArc = antibodyPct * totalArc;

    ctx.beginPath();
    ctx.arc(cx, cy, midR, startAngle, startAngle + totalArc);
    ctx.strokeStyle = 'rgba(55, 65, 81, 0.2)';
    ctx.lineWidth = midWidth;
    ctx.lineCap = 'round';
    ctx.stroke();

    if (antibodyArc > 0) {
      ctx.beginPath();
      ctx.arc(cx, cy, midR, startAngle, startAngle + antibodyArc);
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.6)';
      ctx.lineWidth = midWidth;
      ctx.lineCap = 'round';
      ctx.stroke();
    }

    // ─── Inner ring (threats blocked) ───────────────────────────────

    const innerR = 60;
    const innerWidth = 2;
    const blockedPct = Math.min(threatsBlocked / 50, 1);
    const blockedArc = blockedPct * totalArc;

    ctx.beginPath();
    ctx.arc(cx, cy, innerR, startAngle, startAngle + totalArc);
    ctx.strokeStyle = 'rgba(55, 65, 81, 0.15)';
    ctx.lineWidth = innerWidth;
    ctx.lineCap = 'round';
    ctx.stroke();

    if (blockedArc > 0) {
      ctx.beginPath();
      ctx.arc(cx, cy, innerR, startAngle, startAngle + blockedArc);
      ctx.strokeStyle = 'rgba(167, 139, 250, 0.5)';
      ctx.lineWidth = innerWidth;
      ctx.lineCap = 'round';
      ctx.stroke();
    }

    // ─── Orbiting particles ─────────────────────────────────────────

    for (const p of particlesRef.current) {
      p.angle += p.speed;
      const px = cx + Math.cos(p.angle) * p.radius;
      const py = cy + Math.sin(p.angle) * p.radius;

      const pGlow = ctx.createRadialGradient(px, py, 0, px, py, p.size * 3);
      pGlow.addColorStop(0, `${color}${Math.floor(p.alpha * 255).toString(16).padStart(2, '0')}`);
      pGlow.addColorStop(1, 'transparent');
      ctx.fillStyle = pGlow;
      ctx.beginPath();
      ctx.arc(px, py, p.size * 3, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = `${color}${Math.floor(p.alpha * 200).toString(16).padStart(2, '0')}`;
      ctx.beginPath();
      ctx.arc(px, py, p.size, 0, Math.PI * 2);
      ctx.fill();
    }

    // ─── Center score ───────────────────────────────────────────────

    const breathe = Math.sin(t * 1.5) * 0.03 + 1;
    ctx.save();
    ctx.translate(cx, cy);
    ctx.scale(breathe, breathe);

    // Score number
    ctx.fillStyle = color;
    ctx.font = 'bold 36px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(Math.round(currentScore).toString(), 0, -4);

    // Label
    ctx.fillStyle = 'rgba(209, 213, 219, 0.6)';
    ctx.font = '600 9px Inter, sans-serif';
    ctx.letterSpacing = '2px';
    ctx.fillText(scoreLabel(currentScore), 0, 20);

    ctx.restore();

    // ─── Bottom metrics ─────────────────────────────────────────────

    const metricY = cy + 105;
    ctx.fillStyle = 'rgba(209, 213, 219, 0.4)';
    ctx.font = '9px Inter, sans-serif';
    ctx.textAlign = 'center';

    ctx.fillStyle = 'rgba(56, 189, 248, 0.6)';
    ctx.fillText(`${antibodyCount} antibodies`, cx - 55, metricY);

    ctx.fillStyle = 'rgba(167, 139, 250, 0.6)';
    ctx.fillText(`${threatsBlocked} blocked`, cx + 55, metricY);

    animRef.current = requestAnimationFrame(draw);
  }, [antibodyCount, threatsBlocked]);

  useEffect(() => {
    animRef.current = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(animRef.current);
  }, [draw]);

  return (
    <div className={className}>
      <canvas
        ref={canvasRef}
        className="w-full"
        style={{ width: '100%', height: 260 }}
      />
    </div>
  );
}

export default ImmunityRing;
