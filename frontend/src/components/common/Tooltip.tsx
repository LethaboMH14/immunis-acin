// frontend/src/components/common/Tooltip.tsx
// Tooltip — hover-triggered, positioned, animated, portal-rendered
// WHY: Metric labels, icon buttons, truncated text, status indicators —
// dozens of elements need contextual help text on hover.

import React, { useState, useRef, useCallback, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'framer-motion';

// ─── Types ────────────────────────────────────────────────────────────────────

type TooltipPosition = 'top' | 'bottom' | 'left' | 'right';

interface TooltipProps {
  content: React.ReactNode;
  position?: TooltipPosition;
  delay?: number;
  className?: string;
  children: React.ReactElement;
}

// ─── Animation ────────────────────────────────────────────────────────────────

const tooltipVariants = {
  hidden: { opacity: 0, scale: 0.95 },
  visible: {
    opacity: 1,
    scale: 1,
    transition: { duration: 0.1, ease: 'easeOut' },
  },
  exit: {
    opacity: 0,
    scale: 0.95,
    transition: { duration: 0.075, ease: 'easeIn' },
  },
};

// ─── Component ────────────────────────────────────────────────────────────────

export function Tooltip({
  content,
  position = 'top',
  delay = 300,
  className = '',
  children,
}: TooltipProps) {
  const [isVisible, setIsVisible] = useState(false);
  const [coords, setCoords] = useState({ x: 0, y: 0 });
  const triggerRef = useRef<HTMLElement>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const calculatePosition = useCallback(() => {
    if (!triggerRef.current) return;

    const rect = triggerRef.current.getBoundingClientRect();
    const gap = 8;

    let x = 0;
    let y = 0;

    switch (position) {
      case 'top':
        x = rect.left + rect.width / 2;
        y = rect.top - gap;
        break;
      case 'bottom':
        x = rect.left + rect.width / 2;
        y = rect.bottom + gap;
        break;
      case 'left':
        x = rect.left - gap;
        y = rect.top + rect.height / 2;
        break;
      case 'right':
        x = rect.right + gap;
        y = rect.top + rect.height / 2;
        break;
    }

    setCoords({ x, y });
  }, [position]);

  const showTooltip = useCallback(() => {
    timerRef.current = setTimeout(() => {
      calculatePosition();
      setIsVisible(true);
    }, delay);
  }, [delay, calculatePosition]);

  const hideTooltip = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    setIsVisible(false);
  }, []);

  useEffect(() => {
    return () => {
      if (timerRef.current) {
        clearTimeout(timerRef.current);
      }
    };
  }, []);

  // Position transforms
  const transformMap: Record<TooltipPosition, string> = {
    top: 'translate(-50%, -100%)',
    bottom: 'translate(-50%, 0)',
    left: 'translate(-100%, -50%)',
    right: 'translate(0, -50%)',
  };

  return (
    <>
      {React.cloneElement(children, {
        ref: triggerRef,
        onMouseEnter: showTooltip,
        onMouseLeave: hideTooltip,
        onFocus: showTooltip,
        onBlur: hideTooltip,
      })}
      {createPortal(
        <AnimatePresence>
          {isVisible && (
            <motion.div
              variants={tooltipVariants}
              initial="hidden"
              animate="visible"
              exit="exit"
              className={[
                'fixed z-[70] pointer-events-none',
                'px-2.5 py-1.5 rounded-md',
                'bg-[var(--bg-primary)] border border-[var(--border-primary)]',
                'text-xs text-[var(--text-primary)] font-medium',
                'shadow-[var(--shadow-lg)]',
                'max-w-xs',
                className,
              ]
                .filter(Boolean)
                .join(' ')}
              style={{
                left: coords.x,
                top: coords.y,
                transform: transformMap[position],
              }}
            >
              {content}
            </motion.div>
          )}
        </AnimatePresence>,
        document.body
      )}
    </>
  );
}

export type { TooltipProps, TooltipPosition };
export default Tooltip;
