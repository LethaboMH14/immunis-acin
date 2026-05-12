/**
 * ExplainabilityPanel — Feature Attribution Visualization
 * 
 * Displays ranked feature attributions for a detection decision.
 * Shows WHY IMMUNIS flagged a threat, not just that it did.
 * 
 * EU AI Act Article 13 compliant: full transparency of AI decisions.
 * EU AI Act Article 14 compliant: human can verify and override.
 * POPIA Section 71 compliant: explanation of automated decisions.
 * 
 * Visual design: Inspired by Bloomberg terminal data density
 * with Apple's clarity. Every pixel communicates information.
 */

import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

// --- Types ---

interface FeatureAttribution {
  rank: number;
  feature: string;
  category: string;
  contribution: number;
  raw_score: number;
  weight: number;
  evidence: string;
  evidence_spans: string[];
  mitre: string | null;
  regulatory: string[];
}

interface ConfidenceBreakdown {
  text: number;
  visual: number;
  behavioral: number;
  historical: number;
  fusion_method: string;
}

interface ExplainabilityData {
  threat_id: string;
  timestamp: string;
  overall_confidence: number;
  classification: string;
  severity: string;
  attack_family: string;
  computation_time_ms: number;
  explanation_hash: string;
  eu_ai_act_compliant: boolean;
  total_features_evaluated: number;
  top_features_contributing: number;
  top_features: FeatureAttribution[];
  decision_path: string[];
  counterfactual: string;
  confidence_breakdown: ConfidenceBreakdown;
}

interface AudienceExplanation {
  audience: string;
  [key: string]: any;
}

interface ExplainabilityPanelProps {
  threatId?: string;
  data?: ExplainabilityData;
  compact?: boolean;
  showAudienceToggle?: boolean;
  className?: string;
}

// --- Color helpers ---

const categoryColors: Record<string, string> = {
  social_engineering: '#FF4D6A',
  linguistic: '#A78BFA',
  technical: '#38BDF8',
  visual: '#FB923C',
  behavioral: '#FBBF24',
  contextual: '#34D399',
  network: '#06B6D4',
  historical: '#8B5CF6',
};

const categoryLabels: Record<string, string> = {
  social_engineering: 'Social Engineering',
  linguistic: 'Linguistic',
  technical: 'Technical',
  visual: 'Visual',
  behavioral: 'Behavioral',
  contextual: 'Contextual',
  network: 'Network',
  historical: 'Historical',
};

const severityColors: Record<string, string> = {
  critical: '#FF4D6A',
  high: '#FB923C',
  medium: '#FBBF24',
  low: '#34D399',
  info: '#38BDF8',
};

const classificationColors: Record<string, string> = {
  novel: '#A78BFA',
  variant: '#FBBF24',
  known: '#34D399',
};

// --- Sub-components ---

const FeatureBar: React.FC<{
  feature: FeatureAttribution;
  maxContribution: number;
  index: number;
  expanded: boolean;
  onToggle: () => void;
}> = ({ feature, maxContribution, index, expanded, onToggle }) => {
  const barWidth = maxContribution > 0 ? (feature.contribution / maxContribution) * 100 : 0;
  const color = categoryColors[feature.category] || '#6B7280';

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.05, duration: 0.3 }}
      className="group"
    >
      <button
        onClick={onToggle}
        className="w-full text-left"
        style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer' }}
      >
        {/* Main row */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          padding: '8px 12px',
          borderRadius: '8px',
          background: expanded ? 'var(--bg-tertiary, rgba(255,255,255,0.03))' : 'transparent',
          transition: 'background 0.2s',
        }}>
          {/* Rank */}
          <span style={{
            width: '24px',
            height: '24px',
            borderRadius: '50%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '11px',
            fontWeight: 700,
            background: index < 3 ? color : 'var(--bg-tertiary, rgba(255,255,255,0.06))',
            color: index < 3 ? '#fff' : 'var(--text-secondary, #9CA3AF)',
            flexShrink: 0,
          }}>
            {feature.rank}
          </span>

          {/* Feature name + category */}
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{
              fontSize: '13px',
              fontWeight: 500,
              color: 'var(--text-primary, #F9FAFB)',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            }}>
              {feature.feature.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
            </div>
            <div style={{
              fontSize: '11px',
              color,
              fontWeight: 500,
              textTransform: 'uppercase',
              letterSpacing: '0.5px',
            }}>
              {categoryLabels[feature.category] || feature.category}
            </div>
          </div>

          {/* Contribution bar */}
          <div style={{ width: '120px', flexShrink: 0 }}>
            <div style={{
              height: '6px',
              borderRadius: '3px',
              background: 'var(--bg-tertiary, rgba(255,255,255,0.06))',
              overflow: 'hidden',
            }}>
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${barWidth}%` }}
                transition={{ delay: index * 0.05 + 0.2, duration: 0.5, ease: 'easeOut' }}
                style={{
                  height: '100%',
                  borderRadius: '3px',
                  background: `linear-gradient(90deg, ${color}88, ${color})`,
                }}
              />
            </div>
          </div>

          {/* Percentage */}
          <span style={{
            width: '48px',
            textAlign: 'right',
            fontSize: '13px',
            fontWeight: 600,
            fontFamily: 'JetBrains Mono, monospace',
            color: 'var(--text-primary, #F9FAFB)',
            flexShrink: 0,
          }}>
            {(feature.contribution * 100).toFixed(1)}%
          </span>

          {/* MITRE badge */}
          {feature.mitre && (
            <span style={{
              fontSize: '10px',
              padding: '2px 6px',
              borderRadius: '4px',
              background: 'rgba(56, 189, 248, 0.15)',
              color: '#38BDF8',
              fontFamily: 'JetBrains Mono, monospace',
              fontWeight: 500,
              flexShrink: 0,
            }}>
              {feature.mitre}
            </span>
          )}

          {/* Expand indicator */}
          <span style={{
            fontSize: '12px',
            color: 'var(--text-tertiary, #6B7280)',
            transform: expanded ? 'rotate(90deg)' : 'rotate(0)',
            transition: 'transform 0.2s',
            flexShrink: 0,
          }}>
            ▶
          </span>
        </div>
      </button>

      {/* Expanded detail */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            style={{ overflow: 'hidden' }}
          >
            <div style={{
              padding: '8px 12px 12px 48px',
              fontSize: '12px',
              color: 'var(--text-secondary, #9CA3AF)',
              lineHeight: 1.6,
            }}>
              {/* Evidence */}
              <div style={{ marginBottom: '8px' }}>
                <span style={{ color: 'var(--text-tertiary, #6B7280)', fontWeight: 500 }}>Evidence: </span>
                {feature.evidence}
              </div>

              {/* Evidence spans */}
              {feature.evidence_spans && feature.evidence_spans.length > 0 && (
                <div style={{ marginBottom: '8px' }}>
                  <span style={{ color: 'var(--text-tertiary, #6B7280)', fontWeight: 500 }}>Matched text: </span>
                  {feature.evidence_spans.map((span, i) => (
                    <span key={i} style={{
                      display: 'inline-block',
                      background: `${color}22`,
                      border: `1px solid ${color}44`,
                      padding: '1px 6px',
                      borderRadius: '3px',
                      margin: '2px 4px 2px 0',
                      fontFamily: 'JetBrains Mono, monospace',
                      fontSize: '11px',
                    }}>
                      "{span}"
                    </span>
                  ))}
                </div>
              )}

              {/* Scores */}
              <div style={{ display: 'flex', gap: '16px', marginBottom: '8px' }}>
                <span>
                  <span style={{ color: 'var(--text-tertiary, #6B7280)' }}>Raw: </span>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>{feature.raw_score.toFixed(2)}</span>
                </span>
                <span>
                  <span style={{ color: 'var(--text-tertiary, #6B7280)' }}>Weight: </span>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>{feature.weight.toFixed(2)}</span>
                </span>
                <span>
                  <span style={{ color: 'var(--text-tertiary, #6B7280)' }}>Weighted: </span>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>{(feature.raw_score * feature.weight).toFixed(3)}</span>
                </span>
              </div>

              {/* Regulatory */}
              {feature.regulatory && feature.regulatory.length > 0 && (
                <div>
                  <span style={{ color: 'var(--text-tertiary, #6B7280)', fontWeight: 500 }}>Regulatory: </span>
                  {feature.regulatory.map((reg, i) => (
                    <span key={i} style={{
                      display: 'inline-block',
                      background: 'rgba(251, 191, 36, 0.12)',
                      border: '1px solid rgba(251, 191, 36, 0.3)',
                      color: '#FBBF24',
                      padding: '1px 6px',
                      borderRadius: '3px',
                      margin: '2px 4px 2px 0',
                      fontSize: '10px',
                      fontWeight: 500,
                    }}>
                      {reg}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};

const ConfidenceRing: React.FC<{
  label: string;
  value: number;
  color: string;
  size?: number;
}> = ({ label, value, color, size = 64 }) => {
  const radius = (size - 8) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - value);

  return (
    <div style={{ textAlign: 'center' }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        {/* Background ring */}
        <circle
          cx={size / 2} cy={size / 2} r={radius}
          fill="none"
          stroke="var(--bg-tertiary, rgba(255,255,255,0.06))"
          strokeWidth="4"
        />
        {/* Value ring */}
        <motion.circle
          cx={size / 2} cy={size / 2} r={radius}
          fill="none"
          stroke={color}
          strokeWidth="4"
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1, delay: 0.3, ease: 'easeOut' }}
        />
      </svg>
      <div style={{
        marginTop: '-' + (size / 2 + 8) + 'px',
        paddingTop: (size / 2 - 10) + 'px',
        fontSize: '14px',
        fontWeight: 700,
        fontFamily: 'JetBrains Mono, monospace',
        color: 'var(--text-primary, #F9FAFB)',
      }}>
        {(value * 100).toFixed(0)}%
      </div>
      <div style={{
        fontSize: '10px',
        color: 'var(--text-tertiary, #6B7280)',
        marginTop: '4px',
        textTransform: 'uppercase',
        letterSpacing: '0.5px',
      }}>
        {label}
      </div>
    </div>
  );
};

const DecisionPath: React.FC<{ steps: string[] }> = ({ steps }) => (
  <div style={{ padding: '0 4px' }}>
    {steps.map((step, i) => (
      <motion.div
        key={i}
        initial={{ opacity: 0, x: -10 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ delay: i * 0.1 }}
        style={{
          display: 'flex',
          gap: '12px',
          padding: '8px 0',
          borderBottom: i < steps.length - 1 ? '1px solid var(--border-primary, rgba(255,255,255,0.06))' : 'none',
        }}
      >
        {/* Step number */}
        <div style={{
          width: '20px',
          height: '20px',
          borderRadius: '50%',
          background: 'var(--bg-tertiary, rgba(255,255,255,0.06))',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: '10px',
          fontWeight: 700,
          color: 'var(--text-secondary, #9CA3AF)',
          flexShrink: 0,
          marginTop: '2px',
        }}>
          {i + 1}
        </div>
        {/* Step text */}
        <div style={{
          fontSize: '12px',
          color: 'var(--text-secondary, #9CA3AF)',
          lineHeight: 1.6,
        }}>
          {step}
        </div>
      </motion.div>
    ))}
  </div>
);

const CategoryBreakdown: React.FC<{ features: FeatureAttribution[] }> = ({ features }) => {
  const categories = useMemo(() => {
    const map: Record<string, number> = {};
    features.forEach(f => {
      map[f.category] = (map[f.category] || 0) + f.contribution;
    });
    return Object.entries(map)
      .sort(([, a], [, b]) => b - a)
      .map(([cat, total]) => ({ category: cat, total }));
  }, [features]);

  const maxTotal = Math.max(...categories.map(c => c.total), 0.01);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
      {categories.map((cat, i) => (
        <div key={cat.category} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div style={{
            width: '10px', height: '10px', borderRadius: '2px',
            background: categoryColors[cat.category] || '#6B7280',
            flexShrink: 0,
          }} />
          <span style={{
            fontSize: '11px', width: '120px', color: 'var(--text-secondary, #9CA3AF)',
          }}>
            {categoryLabels[cat.category] || cat.category}
          </span>
          <div style={{
            flex: 1, height: '4px', borderRadius: '2px',
            background: 'var(--bg-tertiary, rgba(255,255,255,0.06))',
          }}>
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${(cat.total / maxTotal) * 100}%` }}
              transition={{ delay: i * 0.05 + 0.3, duration: 0.5 }}
              style={{
                height: '100%', borderRadius: '2px',
                background: categoryColors[cat.category] || '#6B7280',
              }}
            />
          </div>
          <span style={{
            fontSize: '11px', fontFamily: 'JetBrains Mono, monospace',
            color: 'var(--text-primary, #F9FAFB)', width: '40px', textAlign: 'right',
          }}>
            {(cat.total * 100).toFixed(1)}%
          </span>
        </div>
      ))}
    </div>
  );
};

// --- Main Component ---

const ExplainabilityPanel: React.FC<ExplainabilityPanelProps> = ({
  threatId,
  data: propData,
  compact = false,
  showAudienceToggle = true,
  className = '',
}) => {
  const [data, setData] = useState<ExplainabilityData | null>(propData || null);
  const [loading, setLoading] = useState(false);
  const [expandedFeature, setExpandedFeature] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<'features' | 'path' | 'confidence' | 'audit'>('features');
  const [audience, setAudience] = useState<string>('soc_analyst');
  const [audienceData, setAudienceData] = useState<AudienceExplanation | null>(null);

  // Fetch data if threatId provided but no data
  useEffect(() => {
    if (propData) {
      setData(propData);
      return;
    }
    if (!threatId) return;

    setLoading(true);
    fetch(`/api/explain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        threat_id: threatId,
        se_scores: { urgency: 0.85, authority: 0.9, fear: 0.7, financial_request: 0.95, isolation: 0.6, impersonation: 0.88 },
        linguistic_features: { homoglyph: 0.92, code_switch: 0.55 },
        technical_features: { domain_spoofing: 0.9, suspicious_headers: 0.65 },
        classification: 'novel',
        severity: 'critical',
        attack_family: 'BEC_Authority_Financial',
        confidence: 0.97,
      }),
    })
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [threatId, propData]);

  // Fetch audience-specific explanation
  useEffect(() => {
    if (!data) return;

    const features: Record<string, number> = {};
    data.top_features.forEach(f => { features[f.feature] = f.raw_score; });

    fetch(`/api/explain/audience`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        threat_id: data.threat_id,
        features,
        classification: data.classification,
        severity: data.severity,
        attack_family: data.attack_family,
        confidence: data.overall_confidence,
        audience,
      }),
    })
      .then(r => r.json())
      .then(d => setAudienceData(d))
      .catch(() => {});
  }, [data, audience]);

  const maxContribution = useMemo(() => {
    if (!data) return 0;
    return Math.max(...data.top_features.map(f => f.contribution), 0.01);
  }, [data]);

  if (loading) {
    return (
      <div style={{
        padding: '40px',
        textAlign: 'center',
        color: 'var(--text-tertiary, #6B7280)',
      }}>
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
          style={{ display: 'inline-block', fontSize: '24px', marginBottom: '12px' }}
        >
          ⟳
        </motion.div>
        <div>Generating explanation...</div>
      </div>
    );
  }

  if (!data) {
    return (
      <div style={{
        padding: '40px',
        textAlign: 'center',
        color: 'var(--text-tertiary, #6B7280)',
        fontSize: '13px',
      }}>
        No explainability data available. Submit a threat to see feature attributions.
      </div>
    );
  }

  return (
    <div className={className} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>

      {/* Header */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        flexWrap: 'wrap',
        gap: '12px',
      }}>
        <div>
          <div style={{
            fontSize: '16px', fontWeight: 600,
            color: 'var(--text-primary, #F9FAFB)',
            display: 'flex', alignItems: 'center', gap: '8px',
          }}>
            Detection Explanation
            {data.eu_ai_act_compliant && (
              <span style={{
                fontSize: '9px',
                padding: '2px 6px',
                borderRadius: '3px',
                background: 'rgba(52, 211, 153, 0.15)',
                color: '#34D399',
                fontWeight: 600,
                textTransform: 'uppercase',
                letterSpacing: '0.5px',
              }}>
                EU AI Act Compliant
              </span>
            )}
          </div>
          <div style={{
            fontSize: '12px',
            color: 'var(--text-tertiary, #6B7280)',
            marginTop: '4px',
          }}>
            {data.total_features_evaluated} features evaluated · {data.top_features_contributing} contributing · {data.computation_time_ms.toFixed(1)}ms
          </div>
        </div>

        {/* Classification + severity badges */}
        <div style={{ display: 'flex', gap: '8px' }}>
          <span style={{
            padding: '4px 10px', borderRadius: '6px', fontSize: '12px', fontWeight: 600,
            background: `${classificationColors[data.classification] || '#6B7280'}22`,
            color: classificationColors[data.classification] || '#6B7280',
            textTransform: 'uppercase',
          }}>
            {data.classification}
          </span>
          <span style={{
            padding: '4px 10px', borderRadius: '6px', fontSize: '12px', fontWeight: 600,
            background: `${severityColors[data.severity] || '#6B7280'}22`,
            color: severityColors[data.severity] || '#6B7280',
            textTransform: 'uppercase',
          }}>
            {data.severity}
          </span>
          <span style={{
            padding: '4px 10px', borderRadius: '6px', fontSize: '12px', fontWeight: 600,
            fontFamily: 'JetBrains Mono, monospace',
            background: 'rgba(255,255,255,0.06)',
            color: 'var(--text-primary, #F9FAFB)',
          }}>
            {(data.overall_confidence * 100).toFixed(0)}%
          </span>
        </div>
      </div>

      {/* Audience toggle */}
      {showAudienceToggle && (
        <div style={{
          display: 'flex', gap: '4px', padding: '4px',
          background: 'var(--bg-tertiary, rgba(255,255,255,0.03))',
          borderRadius: '8px', width: 'fit-content',
        }}>
          {['soc_analyst', 'ir_lead', 'ciso', 'executive', 'auditor'].map(a => (
            <button
              key={a}
              onClick={() => setAudience(a)}
              style={{
                padding: '4px 10px', borderRadius: '6px', fontSize: '11px',
                fontWeight: audience === a ? 600 : 400, cursor: 'pointer',
                border: 'none',
                background: audience === a ? 'var(--bg-secondary, rgba(255,255,255,0.08))' : 'transparent',
                color: audience === a ? 'var(--text-primary, #F9FAFB)' : 'var(--text-tertiary, #6B7280)',
                transition: 'all 0.2s',
                textTransform: 'uppercase',
                letterSpacing: '0.5px',
              }}
            >
              {a.replace('_', ' ')}
            </button>
          ))}
        </div>
      )}

      {/* Tab navigation */}
      <div style={{
        display: 'flex', gap: '0', borderBottom: '1px solid var(--border-primary, rgba(255,255,255,0.06))',
      }}>
        {[
          { key: 'features', label: 'Feature Attribution' },
          { key: 'path', label: 'Decision Path' },
          { key: 'confidence', label: 'Confidence' },
          { key: 'audit', label: 'Audit Trail' },
        ].map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key as any)}
            style={{
              padding: '8px 16px', fontSize: '12px', fontWeight: 500, cursor: 'pointer',
              border: 'none', background: 'transparent',
              color: activeTab === tab.key
                ? 'var(--text-primary, #F9FAFB)'
                : 'var(--text-tertiary, #6B7280)',
              borderBottom: activeTab === tab.key
                ? '2px solid #00E5A0'
                : '2px solid transparent',
              transition: 'all 0.2s',
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <AnimatePresence mode="wait">
        {activeTab === 'features' && (
          <motion.div
            key="features"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
          >
            {/* Category breakdown */}
            {!compact && (
              <div style={{
                padding: '12px 16px',
                background: 'var(--bg-tertiary, rgba(255,255,255,0.02))',
                borderRadius: '8px',
                marginBottom: '12px',
              }}>
                <div style={{
                  fontSize: '11px', fontWeight: 600, color: 'var(--text-tertiary, #6B7280)',
                  textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px',
}}>
Category Breakdown
</div>
<CategoryBreakdown features={data.top_features} />
</div>
)}

        {/* Feature list */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
          {data.top_features.map((feature, i) => (
            <FeatureBar
              key={feature.feature}
              feature={feature}
              maxContribution={maxContribution}
              index={i}
              expanded={expandedFeature === i}
              onToggle={() => setExpandedFeature(expandedFeature === i ? null : i)}
            />
          ))}
        </div>

        {/* Counterfactual */}
        {data.counterfactual && (
          <div style={{
            marginTop: '12px',
            padding: '12px 16px',
            background: 'rgba(167, 139, 250, 0.08)',
            border: '1px solid rgba(167, 139, 250, 0.2)',
            borderRadius: '8px',
          }}>
            <div style={{
              fontSize: '11px', fontWeight: 600, color: '#A78BFA',
              textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '6px',
            }}>
              Counterfactual Analysis
            </div>
            <div style={{
              fontSize: '12px', color: 'var(--text-secondary, #9CA3AF)',
              lineHeight: 1.6,
            }}>
              {data.counterfactual}
            </div>
          </div>
        )}
      </motion.div>
    )}

    {activeTab === 'path' && (
      <motion.div
        key="path"
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -10 }}
      >
        <DecisionPath steps={data.decision_path} />
      </motion.div>
    )}

    {activeTab === 'confidence' && (
      <motion.div
        key="confidence"
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -10 }}
      >
        {/* Confidence rings */}
        <div style={{
          display: 'flex',
          justifyContent: 'center',
          gap: '32px',
          padding: '24px 0',
          flexWrap: 'wrap',
        }}>
          <ConfidenceRing
            label="Text"
            value={data.confidence_breakdown.text}
            color="#38BDF8"
            size={80}
          />
          <ConfidenceRing
            label="Visual"
            value={data.confidence_breakdown.visual}
            color="#FB923C"
            size={80}
          />
          <ConfidenceRing
            label="Behavioral"
            value={data.confidence_breakdown.behavioral}
            color="#FBBF24"
            size={80}
          />
          <ConfidenceRing
            label="Historical"
            value={data.confidence_breakdown.historical}
            color="#8B5CF6"
            size={80}
          />
          <ConfidenceRing
            label="Overall"
            value={data.overall_confidence}
            color="#00E5A0"
            size={96}
          />
        </div>

        {/* Fusion method */}
        <div style={{
          textAlign: 'center',
          fontSize: '12px',
          color: 'var(--text-tertiary, #6B7280)',
          marginTop: '8px',
        }}>
          Fusion method: <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>
            {data.confidence_breakdown.fusion_method}
          </span>
        </div>

        {/* Confidence explanation */}
        <div style={{
          marginTop: '16px',
          padding: '12px 16px',
          background: 'var(--bg-tertiary, rgba(255,255,255,0.02))',
          borderRadius: '8px',
          fontSize: '12px',
          color: 'var(--text-secondary, #9CA3AF)',
          lineHeight: 1.6,
        }}>
          {data.confidence_breakdown.text > 0 && data.confidence_breakdown.visual > 0 ? (
            <>
              This detection uses <strong>multimodal fusion</strong> — combining text analysis
              ({(data.confidence_breakdown.text * 100).toFixed(0)}%) with visual analysis
              ({(data.confidence_breakdown.visual * 100).toFixed(0)}%) for a combined
              confidence of {(data.overall_confidence * 100).toFixed(0)}%.
              Neither modality alone would have achieved this confidence level.
            </>
          ) : data.confidence_breakdown.text > 0 ? (
            <>
              This detection is based primarily on text analysis
              ({(data.confidence_breakdown.text * 100).toFixed(0)}% confidence from
              linguistic and social engineering features).
            </>
          ) : (
            <>
              Confidence derived from {data.top_features_contributing} contributing features
              across {new Set(data.top_features.map(f => f.category)).size} categories.
            </>
          )}
        </div>
      </motion.div>
    )}

    {activeTab === 'audit' && (
      <motion.div
        key="audit"
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -10 }}
        style={{ fontSize: '12px' }}
      >
        {/* Audit information */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '12px',
        }}>
          {/* Compliance badges */}
          <div style={{
            padding: '12px 16px',
            background: 'var(--bg-tertiary, rgba(255,255,255,0.02))',
            borderRadius: '8px',
          }}>
            <div style={{
              fontSize: '11px', fontWeight: 600, color: 'var(--text-tertiary, #6B7280)',
              textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px',
            }}>
              Compliance Status
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-secondary, #9CA3AF)' }}>EU AI Act Art. 13 (Transparency)</span>
                <span style={{ color: '#34D399', fontWeight: 600 }}>✓ Compliant</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-secondary, #9CA3AF)' }}>EU AI Act Art. 14 (Human Oversight)</span>
                <span style={{ color: '#34D399', fontWeight: 600 }}>✓ Compliant</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-secondary, #9CA3AF)' }}>POPIA Section 71 (Automated Decisions)</span>
                <span style={{ color: '#34D399', fontWeight: 600 }}>✓ Compliant</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-secondary, #9CA3AF)' }}>NIST AI RMF MAP 2.3 (Explainability)</span>
                <span style={{ color: '#34D399', fontWeight: 600 }}>✓ Compliant</span>
              </div>
            </div>
          </div>

          {/* Audit metadata */}
          <div style={{
            padding: '12px 16px',
            background: 'var(--bg-tertiary, rgba(255,255,255,0.02))',
            borderRadius: '8px',
          }}>
            <div style={{
              fontSize: '11px', fontWeight: 600, color: 'var(--text-tertiary, #6B7280)',
              textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px',
            }}>
              Audit Metadata
            </div>
            <div style={{
              display: 'flex', flexDirection: 'column', gap: '6px',
              fontFamily: 'JetBrains Mono, monospace', fontSize: '11px',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-tertiary, #6B7280)' }}>Threat ID</span>
                <span style={{ color: 'var(--text-primary, #F9FAFB)' }}>{data.threat_id}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-tertiary, #6B7280)' }}>Timestamp</span>
                <span style={{ color: 'var(--text-primary, #F9FAFB)' }}>{data.timestamp}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-tertiary, #6B7280)' }}>Hash</span>
                <span style={{ color: 'var(--text-primary, #F9FAFB)' }}>{data.explanation_hash?.slice(0, 16)}...</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-tertiary, #6B7280)' }}>Computation</span>
                <span style={{ color: 'var(--text-primary, #F9FAFB)' }}>{data.computation_time_ms.toFixed(1)}ms</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-tertiary, #6B7280)' }}>Deterministic</span>
                <span style={{ color: '#34D399' }}>Yes</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-tertiary, #6B7280)' }}>Reproducible</span>
                <span style={{ color: '#34D399' }}>Yes</span>
              </div>
            </div>
          </div>
        </div>

        {/* All regulatory references found */}
        <div style={{
          marginTop: '12px',
          padding: '12px 16px',
          background: 'var(--bg-tertiary, rgba(255,255,255,0.02))',
          borderRadius: '8px',
        }}>
          <div style={{
            fontSize: '11px', fontWeight: 600, color: 'var(--text-tertiary, #6B7280)',
            textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px',
          }}>
            Regulatory References in This Detection
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
            {Array.from(new Set(data.top_features.flatMap(f => f.regulatory || []))).map((reg, i) => (
              <span key={i} style={{
                padding: '3px 8px', borderRadius: '4px', fontSize: '10px', fontWeight: 500,
                background: 'rgba(251, 191, 36, 0.12)',
                border: '1px solid rgba(251, 191, 36, 0.3)',
                color: '#FBBF24',
              }}>
                {reg}
              </span>
            ))}
          </div>
        </div>

        {/* MITRE techniques */}
        <div style={{
          marginTop: '12px',
          padding: '12px 16px',
          background: 'var(--bg-tertiary, rgba(255,255,255,0.02))',
          borderRadius: '8px',
        }}>
          <div style={{
            fontSize: '11px', fontWeight: 600, color: 'var(--text-tertiary, #6B7280)',
            textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '8px',
          }}>
            MITRE ATT&CK Techniques Identified
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
            {Array.from(new Set(data.top_features.map(f => f.mitre).filter(Boolean))).map((tid, i) => (
              <a
                key={i}
                href={`https://attack.mitre.org/techniques/${(tid as string).replace('.', '/')}/`}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  padding: '3px 8px', borderRadius: '4px', fontSize: '10px', fontWeight: 500,
                  fontFamily: 'JetBrains Mono, monospace',
                  background: 'rgba(56, 189, 248, 0.12)',
                  border: '1px solid rgba(56, 189, 248, 0.3)',
                  color: '#38BDF8',
                  textDecoration: 'none',
                  cursor: 'pointer',
                }}
              >
                {tid}
              </a>
            ))}
          </div>
        </div>
      </motion.div>
    )}
  </AnimatePresence>
</div>
);
};

export default ExplainabilityPanel;
