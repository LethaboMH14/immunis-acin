// frontend/src/components/common/LoadingScreen.tsx
// Full-screen loading — initial app load, route transitions
// WHY: First impression. While providers initialize, models load, and
// WebSocket connects, the user sees this. Must feel premium and intentional.

import React from 'react';
import { motion } from 'framer-motion';

// ─── Types ────────────────────────────────────────────────────────────────────

interface LoadingScreenProps {
  message?: string;
  progress?: number;
}

// ─── Component ────────────────────────────────────────────────────────────────

export function LoadingScreen({
  message = 'Initialising immune system...',
  progress,
}: LoadingScreenProps) {
  return (
    <div className="fixed inset-0 z-[100] flex flex-col items-center justify-center bg-[#0A0E1A]">
      {/* Logo */}
      <motion.div
        initial={{ opacity: 0, scale: 0.8 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.5, ease: 'easeOut' }}
        className="relative mb-8"
      >
        {/* Shield shape */}
        <svg
          width="64"
          height="72"
          viewBox="0 0 64 72"
          fill="none"
          className="text-[#00E5A0]"
        >
          <path
            d="M32 2L4 16v20c0 17.6 11.9 34 28 38 16.1-4 28-20.4 28-38V16L32 2Z"
            stroke="currentColor"
            strokeWidth="2.5"
            fill="none"
          />
          <path
            d="M32 14L12 24v12c0 11.7 8.5 22.7 20 26 11.5-3.3 20-14.3 20-26V24L32 14Z"
            fill="currentColor"
            fillOpacity="0.1"
          />
          {/* Cross / antibody symbol */}
          <path
            d="M24 36h16M32 28v16"
            stroke="currentColor"
            strokeWidth="2.5"
            strokeLinecap="round"
          />
        </svg>

        {/* Pulse rings */}
        <motion.div
          className="absolute inset-0 rounded-full border-2 border-[#00E5A0]"
          initial={{ opacity: 0.6, scale: 1 }}
          animate={{ opacity: 0, scale: 2.5 }}
          transition={{
            duration: 2,
            repeat: Infinity,
            ease: 'easeOut',
          }}
          style={{ borderRadius: '50%', top: -4, left: -4, right: -4, bottom: -4 }}
        />
        <motion.div
          className="absolute inset-0 rounded-full border border-[#00E5A0]"
          initial={{ opacity: 0.4, scale: 1 }}
          animate={{ opacity: 0, scale: 3 }}
          transition={{
            duration: 2,
            repeat: Infinity,
            ease: 'easeOut',
            delay: 0.5,
          }}
          style={{ borderRadius: '50%', top: -4, left: -4, right: -4, bottom: -4 }}
        />
      </motion.div>

      {/* Title */}
      <motion.h1
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3, duration: 0.4 }}
        className="text-xl font-bold text-white tracking-wider mb-2"
      >
        IMMUNIS
      </motion.h1>

      <motion.p
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5, duration: 0.4 }}
        className="text-xs text-[#00E5A0]/60 tracking-[0.3em] uppercase mb-8"
      >
        Adversarial Coevolutionary Immune Network
      </motion.p>

      {/* Loading message */}
      <motion.p
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.7, duration: 0.4 }}
        className="text-sm text-gray-400"
      >
        {message}
      </motion.p>

      {/* Progress bar */}
      {progress !== undefined && (
        <motion.div
          initial={{ opacity: 0, width: 0 }}
          animate={{ opacity: 1, width: 200 }}
          transition={{ delay: 0.8, duration: 0.3 }}
          className="mt-4 h-0.5 bg-gray-800 rounded-full overflow-hidden"
          style={{ width: 200 }}
        >
          <motion.div
            className="h-full bg-[#00E5A0] rounded-full"
            initial={{ width: 0 }}
            animate={{ width: `${progress}%` }}
            transition={{ duration: 0.3 }}
          />
        </motion.div>
      )}
    </div>
  );
}

export type { LoadingScreenProps };
export default LoadingScreen;
