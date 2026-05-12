/**
 * AttackGraph — Real-Time Kill Chain Visualization
 * 
 * Canvas-based directed attack graph that builds in real-time as
 * IMMUNIS analyzes a threat. Each node represents a MITRE ATT&CK
 * technique in the kill chain. Nodes appear sequentially, connections
 * pulse, and IMMUNIS intervention points glow green.
 * 
 * Visual language:
 * - Red nodes: Attack techniques (what the attacker does)
 * - Green shield overlay: IMMUNIS blocks this technique
 * - Amber nodes: Techniques that would succeed without IMMUNIS
 * - Pulsing connections: Flow direction of the attack
 * - Green "cut" lines: Where IMMUNIS breaks the kill chain
 * 
 * Inspired by:
 * - AttackIQ/SafeBreach attack path visualization
 * - Bloomberg terminal data flow diagrams
 * - Darktrace Cyber AI Analyst kill chain view
 * 
 * References:
 * - Ou et al., "MulVAL" (USENIX 2005)
 * - Sheyner et al., "Automated Generation of Attack Graphs" (IEEE S&P 2002)
 * - MITRE ATT&CK Enterprise v14 Kill Chain
 */

import React, { useRef, useEffect, useState, useCallback } from 'react';

// --- Types ---

interface AttackNode {
  id: string;
  label: string;
  technique_id: string;
  tactic: string;
  description: string;
  blocked: boolean;
  detected: boolean;
  agent: string;   // Which IMMUNIS agent detects/blocks this
  x: number;
  y: number;
  revealed: boolean;
  revealTime: number;
  pulsePhase: number;
}

interface AttackEdge {
  from: string;
  to: string;
  revealed: boolean;
  revealTime: number;
  blocked: boolean; // True if "to" node is blocked (chain is broken)
  particleProgress: number;
}

interface AttackScenario {
  name: string;
  description: string;
  nodes: Omit<AttackNode, 'x' | 'y' | 'revealed' | 'revealTime' | 'pulsePhase'>[];
  edges: Omit<AttackEdge, 'revealed' | 'revealTime' | 'particleProgress'>[];
}

interface AttackGraphProps {
  scenario?: string; // 'bec' | 'ransomware' | 'apt' | 'supply_chain'
  autoPlay?: boolean;
  speed?: number; // ms between node reveals (default 800)
  width?: number;
  height?: number;
  compact?: boolean;
  className?: string;
}

// --- Attack Scenarios ---
// Each scenario maps a real attack to a kill chain graph

const SCENARIOS: Record<string, AttackScenario> = {
  bec: {
    name: 'Business Email Compromise — Sesotho Municipal Fraud',
    description: 'CEO impersonation targeting CFO for R2.45M wire transfer',
    nodes: [
      { id: 'recon', label: 'Reconnaissance', technique_id: 'T1598', tactic: 'reconnaissance', description: 'Research target org, identify CFO, scrape letterhead', blocked: false, detected: true, agent: 'Deception/Honeypot' },
      { id: 'resource', label: 'Domain Setup', technique_id: 'T1583.001', tactic: 'resource-development', description: 'Register masepala-rnangaung.co.za (homoglyph)', blocked: false, detected: true, agent: 'Agent 1 (Analyst)' },
      { id: 'forge', label: 'Invoice Forgery', technique_id: 'T1566.001', tactic: 'resource-development', description: 'Create fake invoice PDF with stolen letterhead', blocked: false, detected: true, agent: 'Agent 8 (Visual)' },
      { id: 'phish', label: 'Spearphish Email', technique_id: 'T1566.001', tactic: 'initial-access', description: 'Send Sesotho BEC email to CFO with urgency pressure', blocked: true, detected: true, agent: 'Agent 1 (Analyst)' },
      { id: 'qr', label: 'QR Phishing', technique_id: 'T1566.002', tactic: 'initial-access', description: 'Embedded QR code → credential harvesting page', blocked: true, detected: true, agent: 'Agent 8 (Visual)' },
      { id: 'cred', label: 'Credential Harvest', technique_id: 'T1078', tactic: 'credential-access', description: 'CFO enters eFiling credentials on fake FNB page', blocked: true, detected: false, agent: '' },
      { id: 'transfer', label: 'Wire Transfer', technique_id: 'T1204.001', tactic: 'execution', description: 'R2,450,000 transferred to attacker account', blocked: true, detected: false, agent: '' },
      { id: 'loss', label: 'Financial Loss', technique_id: '', tactic: 'impact', description: 'R2.45M direct loss + R45M grant at risk', blocked: true, detected: false, agent: '' },
    ],
    edges: [
      { from: 'recon', to: 'resource', blocked: false },
      { from: 'resource', to: 'forge', blocked: false },
      { from: 'forge', to: 'phish', blocked: false },
      { from: 'phish', to: 'qr', blocked: true },
      { from: 'phish', to: 'cred', blocked: true },
      { from: 'qr', to: 'cred', blocked: true },
      { from: 'cred', to: 'transfer', blocked: true },
      { from: 'transfer', to: 'loss', blocked: true },
    ],
  },
  ransomware: {
    name: 'Double-Extortion Ransomware — Healthcare',
    description: 'MedusaLocker 3.0 targeting Gauteng Provincial Health',
    nodes: [
      { id: 'vuln', label: 'VPN Exploit', technique_id: 'T1190', tactic: 'initial-access', description: 'FortiGate CVE-2024-21762 exploitation', blocked: false, detected: true, agent: 'Scanner/Infrastructure' },
      { id: 'cred', label: 'Credential Dump', technique_id: 'T1003.001', tactic: 'credential-access', description: 'Zerologon (CVE-2020-1472) + LSASS dump', blocked: false, detected: true, agent: 'Deception/Capture' },
      { id: 'lateral', label: 'Lateral Movement', technique_id: 'T1021.002', tactic: 'lateral-movement', description: 'PsExec + WMI across domain controllers', blocked: false, detected: true, agent: 'Deception/Honeypot' },
      { id: 'escalate', label: 'Privilege Escalation', technique_id: 'T1068', tactic: 'privilege-escalation', description: 'Domain admin via Zerologon', blocked: false, detected: true, agent: 'Scanner/Dynamic' },
      { id: 'disable', label: 'Defense Evasion', technique_id: 'T1562.001', tactic: 'defense-evasion', description: 'Disable AV, delete shadow copies', blocked: false, detected: true, agent: 'Agent 1 (Analyst)' },
      { id: 'exfil', label: 'Data Exfiltration', technique_id: 'T1567.002', tactic: 'exfiltration', description: '4.7TB via Rclone to Mega.nz', blocked: false, detected: true, agent: 'Scanner/Dynamic' },
      { id: 'encrypt', label: 'Encryption', technique_id: 'T1486', tactic: 'impact', description: 'AES-256-CBC + RSA-2048 on all servers', blocked: true, detected: true, agent: 'Agent 1 (Analyst)' },
      { id: 'backup', label: 'Backup Destruction', technique_id: 'T1490', tactic: 'impact', description: 'Veeam backup deletion + shadow copy wipe', blocked: true, detected: true, agent: 'Scanner/Infrastructure' },
      { id: 'ransom', label: 'Ransom Demand', technique_id: '', tactic: 'impact', description: '150 BTC (~R175M) demand + data leak threat', blocked: true, detected: true, agent: 'Agent 1 (Analyst)' },
    ],
    edges: [
      { from: 'vuln', to: 'cred', blocked: false },
      { from: 'cred', to: 'lateral', blocked: false },
      { from: 'lateral', to: 'escalate', blocked: false },
      { from: 'escalate', to: 'disable', blocked: false },
      { from: 'disable', to: 'exfil', blocked: false },
      { from: 'exfil', to: 'encrypt', blocked: true },
      { from: 'encrypt', to: 'backup', blocked: true },
      { from: 'backup', to: 'ransom', blocked: true },
    ],
  },
  apt: {
    name: 'APT Spearphish — SCADA Infrastructure',
    description: 'Russian APT targeting energy sector SCADA systems',
    nodes: [
      { id: 'recon', label: 'Target Research', technique_id: 'T1595', tactic: 'reconnaissance', description: 'Identify SCADA systems and personnel', blocked: false, detected: true, agent: 'Deception/Honeypot' },
      { id: 'spoof', label: 'Domain Spoofing', technique_id: 'T1583.001', tactic: 'resource-development', description: 'Register energo-securitу.gov.ru (Cyrillic у)', blocked: false, detected: true, agent: 'Agent 1 (Analyst)' },
      { id: 'phish', label: 'Spearphish Email', technique_id: 'T1566.001', tactic: 'initial-access', description: 'Fake FSTEC advisory with malicious .exe + .ps1', blocked: true, detected: true, agent: 'Agent 1 (Analyst)' },
      { id: 'exe', label: 'Binary Execution', technique_id: 'T1204.002', tactic: 'execution', description: 'Victim runs security-patch.bin', blocked: true, detected: false, agent: '' },
      { id: 'ps', label: 'PowerShell Bypass', technique_id: 'T1059.001', tactic: 'execution', description: '-ExecutionPolicy Bypass diagnostic script', blocked: true, detected: true, agent: 'Agent 1 (Analyst)' },
      { id: 'persist', label: 'Persistence', technique_id: 'T1136', tactic: 'persistence', description: 'Create backdoor account on SCADA controller', blocked: true, detected: false, agent: '' },
      { id: 'c2', label: 'C2 Channel', technique_id: 'T1071.001', tactic: 'command-and-control', description: 'HTTPS beacon to attacker infrastructure', blocked: true, detected: false, agent: '' },
      { id: 'scada', label: 'SCADA Control', technique_id: '', tactic: 'impact', description: 'Manipulate industrial control systems', blocked: true, detected: false, agent: '' },
    ],
    edges: [
      { from: 'recon', to: 'spoof', blocked: false },
      { from: 'spoof', to: 'phish', blocked: false },
      { from: 'phish', to: 'exe', blocked: true },
      { from: 'phish', to: 'ps', blocked: true },
      { from: 'ps', to: 'persist', blocked: true },
      { from: 'persist', to: 'c2', blocked: true },
      { from: 'c2', to: 'scada', blocked: true },
    ],
  },
  supply_chain: {
    name: 'Supply Chain Compromise — Semiconductor Firmware',
    description: 'Mandarin firmware update compromise targeting chip manufacturer',
    nodes: [
      { id: 'recon', label: 'Vendor Research', technique_id: 'T1595', tactic: 'reconnaissance', description: 'Identify semiconductor supply chain relationships', blocked: false, detected: true, agent: 'TAF/Clusterer' },
      { id: 'domain', label: 'Domain Spoofing', technique_id: 'T1583.001', tactic: 'resource-development', description: 'Register huaxin-serni.com.cn (rn→m homoglyph)', blocked: false, detected: true, agent: 'Agent 1 (Analyst)' },
      { id: 'advisory', label: 'Fake CERT Advisory', technique_id: 'T1566.001', tactic: 'initial-access', description: 'Spoofed HX-CERT emergency security notice', blocked: true, detected: true, agent: 'Agent 1 (Analyst)' },
      { id: 'firmware', label: 'Malicious Firmware', technique_id: 'T1195.002', tactic: 'initial-access', description: 'Trojanized firmware binary download', blocked: true, detected: true, agent: 'Scanner/Static' },
      { id: 'signing', label: 'Signing Bypass', technique_id: 'T1553.006', tactic: 'defense-evasion', description: 'Bypass secure boot via crafted firmware image', blocked: true, detected: false, agent: '' },
      { id: 'boot', label: 'Boot Persistence', technique_id: 'T1542', tactic: 'persistence', description: 'Attacker controls boot chain of all devices', blocked: true, detected: false, agent: '' },
      { id: 'supply', label: 'Supply Chain Spread', technique_id: 'T1195.002', tactic: 'impact', description: 'Every downstream product compromised', blocked: true, detected: false, agent: '' },
    ],
    edges: [
      { from: 'recon', to: 'domain', blocked: false },
      { from: 'domain', to: 'advisory', blocked: false },
      { from: 'advisory', to: 'firmware', blocked: true },
      { from: 'firmware', to: 'signing', blocked: true },
      { from: 'signing', to: 'boot', blocked: true },
      { from: 'boot', to: 'supply', blocked: true },
    ],
  },
};

// --- Tactic colors and ordering ---

const TACTIC_COLORS: Record<string, string> = {
  'reconnaissance': '#6B7280',
  'resource-development': '#8B5CF6',
  'initial-access': '#FF4D6A',
  'execution': '#EF4444',
  'persistence': '#DC2626',
  'privilege-escalation': '#B91C1C',
  'defense-evasion': '#F59E0B',
  'credential-access': '#D97706',
  'discovery': '#92400E',
  'lateral-movement': '#F97316',
  'collection': '#FB923C',
  'command-and-control': '#7C3AED',
  'exfiltration': '#A855F7',
  'impact': '#FF4D6A',
};

const TACTIC_ORDER = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact',
];

// --- Layout engine ---

function layoutNodes(
  scenario: AttackScenario,
  width: number,
  height: number,
): AttackNode[] {
  const padding = { top: 60, bottom: 40, left: 60, right: 60 };
  const plotW = width - padding.left - padding.right;
  const plotH = height - padding.top - padding.bottom;

  // Group by tactic, assign columns
  const tacticGroups: Record<string, typeof scenario.nodes> = {};
  scenario.nodes.forEach(n => {
    if (!tacticGroups[n.tactic]) tacticGroups[n.tactic] = [];
    tacticGroups[n.tactic].push(n);
  });

  // Get unique tactics in order
  const usedTactics = TACTIC_ORDER.filter(t => tacticGroups[t]);
  const colCount = usedTactics.length;

  const nodes: AttackNode[] = [];

  usedTactics.forEach((tactic, colIdx) => {
    const group = tacticGroups[tactic];
    const x = padding.left + (colIdx / Math.max(colCount - 1, 1)) * plotW;

    group.forEach((n, rowIdx) => {
      const rowCount = group.length;
      const yStart = padding.top + plotH * 0.2;
      const yRange = plotH * 0.6;
      const y = rowCount === 1
        ? padding.top + plotH / 2
        : yStart + (rowIdx / Math.max(rowCount - 1, 1)) * yRange;

      nodes.push({
        ...n,
        x,
        y,
        revealed: false,
        revealTime: 0,
        pulsePhase: Math.random() * Math.PI * 2,
      });
    });
  });

  return nodes;
}

// --- Canvas Renderer ---

const AttackGraph: React.FC<AttackGraphProps> = ({
  scenario: scenarioKey = 'bec',
  autoPlay = true,
  speed = 800,
  width: propWidth,
  height: propHeight,
  compact = false,
  className = '',
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const animRef = useRef<number>(0);
  const startTimeRef = useRef<number>(0);
  const nodesRef = useRef<AttackNode[]>([]);
  const edgesRef = useRef<AttackEdge[]>([]);
  const [hoveredNode, setHoveredNode] = useState<AttackNode | null>(null);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });
  const [selectedScenario, setSelectedScenario] = useState(scenarioKey);
  const [isPlaying, setIsPlaying] = useState(autoPlay);
  const [revealIndex, setRevealIndex] = useState(0);

  const w = propWidth || (compact ? 500 : 800);
  const h = propHeight || (compact ? 300 : 420);

  // Initialize scenario
  const initScenario = useCallback((key: string) => {
    const scenario = SCENARIOS[key];
    if (!scenario) return;

    const nodes = layoutNodes(scenario, w, h);
    const edges: AttackEdge[] = scenario.edges.map(e => ({
      ...e,
      revealed: false,
      revealTime: 0,
      particleProgress: 0,
    }));

    nodesRef.current = nodes;
    edgesRef.current = edges;
    startTimeRef.current = performance.now();
    setRevealIndex(0);
    setHoveredNode(null);
  }, [w, h]);

  useEffect(() => {
    initScenario(selectedScenario);
  }, [selectedScenario, initScenario]);

  // Reveal nodes over time
  useEffect(() => {
    if (!isPlaying) return;

    const timer = setInterval(() => {
      setRevealIndex(prev => {
        const next = prev + 1;
        const nodes = nodesRef.current;
        if (next <= nodes.length) {
          // Reveal the next node
          if (nodes[next - 1]) {
            nodes[next - 1].revealed = true;
            nodes[next - 1].revealTime = performance.now();
          }
          // Reveal edges where both endpoints are revealed
          edgesRef.current.forEach(edge => {
            const fromNode = nodes.find(n => n.id === edge.from);
            const toNode = nodes.find(n => n.id === edge.to);
            if (fromNode?.revealed && toNode?.revealed && !edge.revealed) {
              edge.revealed = true;
              edge.revealTime = performance.now();
            }
          });
        }
        if (next >= nodes.length + 3) {
          // All revealed + pause
          clearInterval(timer);
        }
        return next;
      });
    }, speed);

    return () => clearInterval(timer);
  }, [isPlaying, speed, selectedScenario]);

  // Mouse tracking
  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;
    const x = (e.clientX - rect.left) * (w / rect.width);
    const y = (e.clientY - rect.top) * (h / rect.height);
    setMousePos({ x, y });

    // Check hover
    let found: AttackNode | null = null;
    for (const node of nodesRef.current) {
      if (!node.revealed) continue;
      const dx = node.x - x;
      const dy = node.y - y;
      if (Math.sqrt(dx * dx + dy * dy) < 24) {
        found = node;
        break;
      }
    }
    setHoveredNode(found);
  }, [w, h]);

  // Canvas render loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.scale(dpr, dpr);

    const render = () => {
      const now = performance.now();
      ctx.clearRect(0, 0, w, h);

      // Background
      ctx.fillStyle = 'rgba(10, 14, 26, 0.95)';
      ctx.fillRect(0, 0, w, h);

      // Subtle grid
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.02)';
      ctx.lineWidth = 1;
      for (let x = 0; x < w; x += 40) {
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
      }
      for (let y = 0; y < h; y += 40) {
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
      }

      // Draw tactic labels at top
      const usedTactics = Array.from(new Set(nodesRef.current.map(n => n.tactic)));
      const tacticPositions: Record<string, number> = {};
      nodesRef.current.forEach(n => {
        if (!tacticPositions[n.tactic]) tacticPositions[n.tactic] = n.x;
      });
      Object.entries(tacticPositions).forEach(([tactic, x]) => {
        ctx.fillStyle = TACTIC_COLORS[tactic] || '#6B7280';
        ctx.font = '9px Inter, sans-serif';
        ctx.textAlign = 'center';
        const label = tactic.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
        ctx.fillText(label, x, 20);
      });

      // Draw edges
      edgesRef.current.forEach(edge => {
        if (!edge.revealed) return;

        const fromNode = nodesRef.current.find(n => n.id === edge.from);
        const toNode = nodesRef.current.find(n => n.id === edge.to);
        if (!fromNode || !toNode) return;

        const age = (now - edge.revealTime) / 1000;
        const fadeIn = Math.min(age / 0.5, 1);

        // Edge line
        if (edge.blocked) {
          // Blocked edge — dashed red with green "cut" mark
          ctx.strokeStyle = 'rgba(255, 77, 106, ' + (0.3 * fadeIn) + ')';
          ctx.setLineDash([6, 4]);
          ctx.lineWidth = 1.5;
        } else {
          // Active edge — solid with tactic color
          const color = TACTIC_COLORS[toNode.tactic] || '#6B7280';
          ctx.strokeStyle = color + Math.floor(fadeIn * 0.6 * 255).toString(16).padStart(2, '0');
          ctx.setLineDash([]);
          ctx.lineWidth = 2;
        }

        ctx.beginPath();
        ctx.moveTo(fromNode.x, fromNode.y);
        ctx.lineTo(toNode.x, toNode.y);
        ctx.stroke();
        ctx.setLineDash([]);

        // Flowing particle on active edges
        if (!edge.blocked && fadeIn >= 1) {
          edge.particleProgress = (edge.particleProgress + 0.008) % 1;
          const px = fromNode.x + (toNode.x - fromNode.x) * edge.particleProgress;
          const py = fromNode.y + (toNode.y - fromNode.y) * edge.particleProgress;

          ctx.beginPath();
          ctx.arc(px, py, 3, 0, Math.PI * 2);
          const particleColor = TACTIC_COLORS[toNode.tactic] || '#FF4D6A';
          ctx.fillStyle = particleColor;
          ctx.fill();

          // Glow
          ctx.beginPath();
          ctx.arc(px, py, 6, 0, Math.PI * 2);
          ctx.fillStyle = particleColor + '33';
          ctx.fill();
        }

        // Green "cut" mark on blocked edges
        if (edge.blocked && fadeIn >= 0.8) {
          const midX = (fromNode.x + toNode.x) / 2;
          const midY = (fromNode.y + toNode.y) / 2;
          
          // Cut line
          const cutFade = Math.min((age - 0.4) / 0.3, 1);
          if (cutFade > 0) {
            ctx.strokeStyle = 'rgba(255, 77, 106, ' + (0.8 * cutFade) + ')';
            ctx.lineWidth = 3;
            ctx.beginPath();
            // Perpendicular cut
            const dx = toNode.x - fromNode.x;
            const dy = toNode.y - fromNode.y;
            const len = Math.sqrt(dx * dx + dy * dy);
            const nx = -dy / len * 10;
            const ny = dx / len * 10;
            ctx.moveTo(midX + nx, midY + ny);
            ctx.lineTo(midX - nx, midY - ny);
            ctx.stroke();

            // Cut glow
            ctx.beginPath();
            ctx.arc(midX, midY, 8, 0, Math.PI * 2);
            ctx.fillStyle = 'rgba(0, 229, 160, ' + (0.15 * cutFade) + ')';
            ctx.fill();
          }
        }

        // Arrow head
        if (fadeIn >= 0.5) {
          const dx = toNode.x - fromNode.x;
          const dy = toNode.y - fromNode.y;
          const len = Math.sqrt(dx * dx + dy * dy);
          const ux = dx / len;
          const uy = dy / len;
          const arrowDist = 22; // Distance from center of target node
          const ax = toNode.x - ux * arrowDist;
          const ay = toNode.y - uy * arrowDist;
          const arrowSize = 6;

          ctx.fillStyle = edge.blocked
            ? 'rgba(255, 77, 106, ' + (0.4 * fadeIn) + ')'
            : (TACTIC_COLORS[toNode.tactic] || '#6B7280') + Math.floor(fadeIn * 0.7 * 255).toString(16).padStart(2, '0');
          ctx.beginPath();
          ctx.moveTo(ax, ay);
          ctx.lineTo(ax - ux * arrowSize + uy * arrowSize * 0.5, ay - uy * arrowSize - ux * arrowSize * 0.5);
          ctx.lineTo(ax - ux * arrowSize - uy * arrowSize * 0.5, ay - uy * arrowSize + ux * arrowSize * 0.5);
          ctx.closePath();
          ctx.fill();
        }
      });

      // Draw nodes
      nodesRef.current.forEach(node => {
        if (!node.revealed) return;

        const age = (now - node.revealTime) / 1000;
        const fadeIn = Math.min(age / 0.4, 1);
        const scaleIn = 0.3 + 0.7 * Math.min(age / 0.3, 1);
        const radius = 18 * scaleIn;
        const pulse = Math.sin(now / 800 + node.pulsePhase) * 0.5 + 0.5;

        const isHovered = hoveredNode?.id === node.id;

        // Node glow
        if (node.blocked && node.detected) {
          // Blocked + Detected = green glow (IMMUNIS intervened)
          const glowRadius = radius + 8 + pulse * 4;
          const gradient = ctx.createRadialGradient(node.x, node.y, radius, node.x, node.y, glowRadius);
          gradient.addColorStop(0, 'rgba(0, 229, 160, ' + (0.3 * fadeIn) + ')');
          gradient.addColorStop(1, 'rgba(0, 229, 160, 0)');
          ctx.beginPath();
          ctx.arc(node.x, node.y, glowRadius, 0, Math.PI * 2);
          ctx.fillStyle = gradient;
          ctx.fill();
        } else if (node.detected && !node.blocked) {
          // Detected but not blocked (early kill chain — observed)
          const glowRadius = radius + 6 + pulse * 3;
          const gradient = ctx.createRadialGradient(node.x, node.y, radius, node.x, node.y, glowRadius);
          gradient.addColorStop(0, 'rgba(251, 191, 36, ' + (0.2 * fadeIn) + ')');
          gradient.addColorStop(1, 'rgba(251, 191, 36, 0)');
          ctx.beginPath();
          ctx.arc(node.x, node.y, glowRadius, 0, Math.PI * 2);
          ctx.fillStyle = gradient;
          ctx.fill();
        }

        // Node circle
        const tacticColor = TACTIC_COLORS[node.tactic] || '#6B7280';
        ctx.beginPath();
        ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);

        if (node.blocked) {
          // Blocked node — dark fill with green border
          ctx.fillStyle = 'rgba(10, 14, 26, ' + (0.9 * fadeIn) + ')';
          ctx.fill();
          ctx.strokeStyle = 'rgba(0, 229, 160, ' + (0.8 * fadeIn) + ')';
          ctx.lineWidth = 2.5;
          ctx.stroke();
        } else if (node.detected) {
          // Detected but not blocked — amber border
          ctx.fillStyle = tacticColor + Math.floor(0.2 * fadeIn * 255).toString(16).padStart(2, '0');
          ctx.fill();
          ctx.strokeStyle = 'rgba(251, 191, 36, ' + (0.7 * fadeIn) + ')';
          ctx.lineWidth = 2;
          ctx.stroke();
        } else {
          // Undetected — red fill (would have succeeded)
          ctx.fillStyle = tacticColor + Math.floor(0.3 * fadeIn * 255).toString(16).padStart(2, '0');
          ctx.fill();
          ctx.strokeStyle = 'rgba(255, 77, 106, ' + (0.5 * fadeIn) + ')';
          ctx.lineWidth = 1.5;
          ctx.stroke();
        }

        // Shield icon on blocked nodes
        if (node.blocked && fadeIn >= 0.7) {
          const shieldFade = Math.min((age - 0.3) / 0.3, 1);
          ctx.fillStyle = 'rgba(0, 229, 160, ' + (0.9 * shieldFade) + ')';
          ctx.font = '' + (12 * scaleIn) + 'px sans-serif';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillText('🛡️', node.x, node.y);
        } else if (!node.blocked && node.detected) {
          // Eye icon on detected-but-not-blocked nodes
          ctx.fillStyle = 'rgba(251, 191, 36, ' + (0.8 * fadeIn) + ')';
          ctx.font = '' + (10 * scaleIn) + 'px sans-serif';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillText('👁', node.x, node.y);
        }

        // Node label
        ctx.fillStyle = 'rgba(249, 250, 251, ' + (0.9 * fadeIn) + ')';
        ctx.font = '' + (isHovered ? 'bold ' : '') + (compact ? '9' : '10') + 'px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.fillText(node.label, node.x, node.y + radius + 4);

        // Technique ID (small)
        if (node.technique_id && !compact) {
          ctx.fillStyle = 'rgba(156, 163, 175, ' + (0.6 * fadeIn) + ')';
          ctx.font = '8px JetBrains Mono, monospace';
          ctx.fillText(node.technique_id, node.x, node.y + radius + 16);
        }

        // Hover highlight
        if (isHovered) {
          ctx.beginPath();
          ctx.arc(node.x, node.y, radius + 4, 0, Math.PI * 2);
          ctx.strokeStyle = 'rgba(255, 255, 255, 0.3)';
          ctx.lineWidth = 1;
          ctx.stroke();
        }
      });

      // Title
      const scenario = SCENARIOS[selectedScenario];
      if (scenario && !compact) {
        ctx.fillStyle = 'rgba(249, 250, 251, 0.8)';
        ctx.font = 'bold 13px Inter, sans-serif';
        ctx.textAlign = 'left';
        ctx.textBaseline = 'top';
        ctx.fillText(scenario.name, 16, h - 32);
        ctx.fillStyle = 'rgba(156, 163, 175, 0.6)';
        ctx.font = '10px Inter, sans-serif';
        ctx.fillText(scenario.description, 16, h - 18);
      }

      // Legend (top right)
      if (!compact) {
        const legendX = w - 160;
        const legendY = 36;
        ctx.fillStyle = 'rgba(255, 255, 255, 0.05)';
        ctx.fillRect(legendX - 8, legendY - 8, 168, 76);

        const legendItems = [
          { color: '#00E5A0', label: 'IMMUNIS Blocked', icon: '🛡️' },
          { color: '#FBBF24', label: 'Detected (Observed)', icon: '👁' },
          { color: '#FF4D6A', label: 'Attack Technique', icon: '' },
          { color: '#00E5A0', label: 'Kill Chain Cut', icon: '✂' },
        ];

        legendItems.forEach((item, i) => {
          const y = legendY + i * 16;
          ctx.fillStyle = item.color;
          ctx.beginPath();
          ctx.arc(legendX + 4, y + 4, 4, 0, Math.PI * 2);
          ctx.fill();
          ctx.fillStyle = 'rgba(156, 163, 175, 0.7)';
          ctx.font = '9px Inter, sans-serif';
          ctx.textAlign = 'left';
          ctx.fillText('' + item.icon + ' ' + item.label, legendX + 14, y + 7);
        });
      }
    };

    animRef.current = requestAnimationFrame(render);
    return () => cancelAnimationFrame(animRef.current);
  }, [w, h, hoveredNode, selectedScenario, compact]);

  // Reset and replay
  const replay = () => {
    initScenario(selectedScenario);
    setIsPlaying(true);
  };

  return (
    <div className={className} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      {/* Header + controls */}
      {!compact && (
        <div style={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px',
        }}>
          <div>
            <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-primary, #F9FAFB)' }}>
              Attack Kill Chain Graph
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-tertiary, #6B7280)', marginTop: '2px' }}>
              Real-time MITRE ATT&CK technique mapping • Green = IMMUNIS intervention
            </div>
          </div>
          <div style={{ display: 'flex', gap: '6px' }}>
            {Object.entries(SCENARIOS).map(([key, s]) => (
              <button
                key={key}
                onClick={() => { setSelectedScenario(key); setIsPlaying(true); }}
                style={{
                  padding: '4px 10px', borderRadius: '6px', fontSize: '10px',
                  border: selectedScenario === key ? '1px solid #00E5A0' : '1px solid var(--border-primary, rgba(255,255,255,0.06))',
                  background: selectedScenario === key ? 'rgba(0, 229, 160, 0.08)' : 'transparent',
                  color: selectedScenario === key ? '#00E5A0' : 'var(--text-tertiary, #6B7280)',
                  cursor: 'pointer', transition: 'all 0.2s',
                  fontWeight: selectedScenario === key ? 600 : 400,
                }}
              >
                {key.toUpperCase()}
              </button>
            ))}
            <button
              onClick={replay}
              style={{
                padding: '4px 10px', borderRadius: '6px', fontSize: '10px',
                border: '1px solid var(--border-primary, rgba(255,255,255,0.06))',
                background: 'transparent',
                color: 'var(--text-tertiary, #6B7280)',
                cursor: 'pointer',
              }}
            >
              ↻ Replay
            </button>
          </div>
        </div>
      )}

      {/* Canvas */}
      <div
        ref={containerRef}
        style={{
          position: 'relative',
          borderRadius: '10px',
          overflow: 'hidden',
          border: '1px solid var(--border-primary, rgba(255,255,255,0.06))',
        }}
      >
        <canvas
          ref={canvasRef}
          style={{ width: '' + w + 'px', height: '' + h + 'px', display: 'block', cursor: hoveredNode ? 'pointer' : 'default' }}
          onMouseMove={handleMouseMove}
          onMouseLeave={() => setHoveredNode(null)}
        />

        {/* Tooltip */}
        {hoveredNode && (
          <div style={{
            position: 'absolute',
            left: mousePos.x + 16,
            top: mousePos.y - 10,
            padding: '10px 14px',
            background: 'rgba(17, 24, 39, 0.95)',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            borderRadius: '8px',
            maxWidth: '280px',
            pointerEvents: 'none',
            zIndex: 10,
            backdropFilter: 'blur(8px)',
          }}>
            <div style={{
              fontSize: '12px', fontWeight: 600,
                color: hoveredNode.blocked ? '#00E5A0' : hoveredNode.detected ? '#FBBF24' : '#FF4D6A',
                marginBottom: '4px',
              }}>
              {hoveredNode.blocked ? '🛡️ BLOCKED' : hoveredNode.detected ? '👁 DETECTED' : '⚠️ UNDETECTED'}
              {' ' + hoveredNode.label}
            </div>
            {hoveredNode.technique_id && (
              <div style={{
                fontSize: '10px', fontFamily: 'JetBrains Mono, monospace',
                  color: '#38BDF8', marginBottom: '4px',
              }}>
                {hoveredNode.technique_id + ' — ' + hoveredNode.tactic.replace(/-/g, ' ')}
              </div>
            )}
            <div style={{
              fontSize: '11px', color: 'var(--text-secondary, #9CA3AF)', lineHeight: 1.5,
            }}>
              {hoveredNode.description}
            </div>
            {hoveredNode.agent && (
              <div style={{
                fontSize: '10px', color: '#00E5A0', marginTop: '4px', fontWeight: 500,
              }}>
                Detected by: {hoveredNode.agent}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Stats bar */}
      {!compact && (
        <div style={{
          display: 'flex', gap: '16px', flexWrap: 'wrap',
          padding: '8px 12px',
          background: 'var(--bg-tertiary, rgba(255,255,255,0.02))',
          borderRadius: '8px',
          fontSize: '11px',
        }}>
          {(() => {
            const revealed = nodesRef.current.filter(n => n.revealed);
            const blocked = revealed.filter(n => n.blocked);
            const detected = revealed.filter(n => n.detected);
            const blockedEdges = edgesRef.current.filter(e => e.revealed && e.blocked);
            return (
              <>
                <span style={{ color: 'var(--text-tertiary, #6B7280)' }}>
                  Techniques: <span style={{ color: 'var(--text-primary, #F9FAFB)', fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>{revealed.length}/{nodesRef.current.length}</span>
                </span>
                <span style={{ color: 'var(--text-tertiary, #6B7280)' }}>
                  Blocked: <span style={{ color: '#00E5A0', fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>{blocked.length}</span>
                </span>
                <span style={{ color: 'var(--text-tertiary, #6B7280)' }}>
                  Detected: <span style={{ color: '#FBBF24', fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>{detected.length}</span>
                </span>
                <span style={{ color: 'var(--text-tertiary, #6B7280)' }}>
                  Kill Chains Cut: <span style={{ color: '#00E5A0', fontFamily: 'JetBrains Mono, monospace', fontWeight: 600 }}>{blockedEdges.length}</span>
                </span>
              </>
            );
          })()}
        </div>
      )}
    </div>
  );
};

export default AttackGraph;
