// frontend/src/pages/ThreatsPage.tsx
// Threats page — submit, view, and analyse threats
// WHY: The primary interaction page. Judges paste threats here, watch
// the pipeline process them, and see results appear in real time.

import React, { useState, useCallback } from 'react';
import { motion } from 'framer-motion';
import { useImmunis } from '../hooks/useImmunis';
import { Tabs } from '../components/common/Tabs';
import { Card } from '../components/common/Card';
import { Button } from '../components/common/Button';
import { Badge } from '../components/common/Badge';
import { Select } from '../components/common/Select';
import { TextArea } from '../components/common/Input';
import { SlidePanel } from '../components/common/SlidePanel';
import { ThreatFeed } from '../components/overview/ThreatFeed';
import { ThreatDetail } from '../components/threats/ThreatDetail';
import { ThreatStats } from '../components/threats/ThreatStats';
import { LanguageBreakdown } from '../components/threats/LanguageBreakdown';
import { AttackGraph } from '../components/visualizations';
import { ExplainabilityPanel } from '../components/explainability';
import type { Threat } from '../utils/types';

// ─── Constants ────────────────────────────────────────────────────────────────

const VECTOR_OPTIONS = [
  { value: 'email', label: 'Email' },
  { value: 'voice', label: 'Voice / Vishing' },
  { value: 'network', label: 'Network Traffic' },
  { value: 'endpoint', label: 'Endpoint' },
  { value: 'visual', label: 'Visual (Image/QR/Doc)' },
];

const LANGUAGE_OPTIONS = [
  { value: '', label: 'Auto-detect' },
  { value: 'en', label: 'English' },
  { value: 'zu', label: 'isiZulu' },
  { value: 'st', label: 'Sesotho' },
  { value: 'xh', label: 'isiXhosa' },
  { value: 'af', label: 'Afrikaans' },
  { value: 'ar', label: 'Arabic (العربية)' },
  { value: 'zh', label: 'Chinese (中文)' },
  { value: 'ru', label: 'Russian (Русский)' },
  { value: 'fr', label: 'French' },
  { value: 'es', label: 'Spanish' },
  { value: 'sw', label: 'Kiswahili' },
];

const TABS = [
  { id: 'feed', label: 'Threat Feed' },
  { id: 'submit', label: 'Submit Threat' },
  { id: 'stats', label: 'Statistics' },
];

// ─── Component ────────────────────────────────────────────────────────────────

function ThreatsPage() {
  const { threats, submitThreat, pipelineState } = useImmunis();
  const [activeTab, setActiveTab] = useState('feed');
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);

  // Submit form state
  const [threatContent, setThreatContent] = useState('');
  const [vector, setVector] = useState('email');
  const [languageHint, setLanguageHint] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = useCallback(async () => {
    if (!threatContent.trim()) return;

    setIsSubmitting(true);
    try {
      await submitThreat(threatContent, vector, languageHint || undefined);
      setThreatContent('');
      setActiveTab('feed');
    } catch (err) {
      console.error('[ThreatsPage] Submit failed:', err);
    } finally {
      setIsSubmitting(false);
    }
  }, [threatContent, vector, languageHint, submitThreat]);

  const isProcessing = pipelineState !== null;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-[var(--text-primary)]">
            Threat Intelligence
          </h2>
          <p className="text-sm text-[var(--text-muted)]">
            Submit, analyse, and track threats across 40+ languages
          </p>
        </div>
        {isProcessing && (
          <Badge variant="immune" dot>
            Pipeline Active — Stage {pipelineState.stage}/7
          </Badge>
        )}
      </div>

      {/* Tabs */}
      <Tabs tabs={TABS} activeTab={activeTab} onTabChange={setActiveTab} />

      {/* Tab Content */}
      {activeTab === 'feed' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-8">
            <ThreatFeed
              threats={threats}
              onThreatClick={(t) => setSelectedThreat(t)}
            />
          </div>
          <div className="lg:col-span-4">
            <LanguageBreakdown threats={threats} />
          </div>
        </div>
      )}

      {activeTab === 'submit' && (
        <div className="max-w-2xl">
          <Card padding="lg">
            <div className="space-y-5">
              {/* Threat content */}
              <TextArea
                label="Threat Content"
                placeholder="Paste a suspicious email, message, code snippet, or describe a network event..."
                value={threatContent}
                onChange={(e) => setThreatContent(e.target.value)}
                autoResize
                maxRows={15}
                helperText="Supports 40+ languages. PII is automatically scrubbed before analysis."
              />

              {/* Options row */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <Select
                  label="Attack Vector"
                  options={VECTOR_OPTIONS}
                  value={vector}
                  onChange={(e) => setVector(e.target.value)}
                />
                <Select
                  label="Language Hint"
                  options={LANGUAGE_OPTIONS}
                  value={languageHint}
                  onChange={(e) => setLanguageHint(e.target.value)}
                  helperText="Optional — auto-detection works for most languages"
                />
              </div>

              {/* Submit button */}
              <div className="flex items-center justify-between pt-2">
                <p className="text-xs text-[var(--text-muted)]">
                  {threatContent.length > 0
                    ? `${threatContent.length} characters` 
                    : 'Paste threat content to begin'}
                </p>
                <Button
                  variant="primary"
                  isLoading={isSubmitting}
                  disabled={!threatContent.trim() || isSubmitting}
                  onClick={handleSubmit}
                >
                  {isSubmitting ? 'Analysing...' : 'Analyse Threat'}
                </Button>
              </div>
            </div>
          </Card>

          {/* Sample threats for demo */}
          <Card title="Sample Threats (Demo)" padding="sm" className="mt-4">
            <div className="space-y-2">
              {[
                {
                  label: 'Sesotho BEC Email',
                  content: 'Motswalle wa ka, ke kopa thuso ea ka ka potlako. Ke lahlehetsoe ke mokotla oa ka le karete ea banka ha ke le leetong la mosebetsi Johannesburg. Ke hloka hore o nthomelele R5,000 ka e-wallet ho 071-555-0123 hore ke tle ke khone ho khutlela hae. Ke tla o lefa hosane ha ke fihla. Ke taba ea tshohanyetso.',
                },
                {
                  label: 'isiZulu Authority Phishing',
                  content: 'Sawubona, ngiyintombi kaSARS. Umkhokha wakho wentela unenkinga. Uma ungakhokhi R15,000 namhlanje, sizovala i-akhawunti yakho. Thumela imali ku: FNB 62345678901. Ungabikeli muntu.',
                },
                {
                  label: 'Arabic Invoice Fraud',
                  content: 'عزيزي المدير المالي، تم تغيير تفاصيل الحساب البنكي لشركتنا. يرجى تحديث سجلاتكم وإرسال الدفعة القادمة إلى: بنك الإمارات دبي الوطني، حساب رقم ٩٨٧٦٥٤٣٢١٠. هذا عاجل ويجب التحويل اليوم.',
                },
              ].map((sample) => (
                <button
                  key={sample.label}
                  onClick={() => setThreatContent(sample.content)}
                  className="w-full text-left px-3 py-2 rounded-lg hover:bg-[var(--bg-tertiary)] transition-colors group"
                >
                  <p className="text-xs font-medium text-[var(--text-secondary)] group-hover:text-[var(--text-primary)]">
                    {sample.label}
                  </p>
                  <p className="text-[10px] text-[var(--text-muted)] truncate mt-0.5">
                    {sample.content.slice(0, 80)}...
                  </p>
                </button>
              ))}
            </div>
          </Card>
        </div>
      )}

      {activeTab === 'stats' && (
        <ThreatStats threats={threats} />
      )}

      {/* Detail Panel */}
      <SlidePanel
        isOpen={!!selectedThreat}
        onClose={() => setSelectedThreat(null)}
        title="Threat Details"
        subtitle={selectedThreat?.incident_id}
        size="lg"
      >
        {selectedThreat && <ThreatDetail threat={selectedThreat} />}
      </SlidePanel>

      {/* Attack Kill Chain */}
      <div style={{
        padding: '16px',
        background: 'var(--bg-secondary, #111827)',
        borderRadius: '12px',
        border: '1px solid var(--border-primary, rgba(255,255,255,0.06))',
      }}>
        <AttackGraph
          scenario="bec"
          autoPlay={true}
          speed={800}
        />
      </div>

      {/* Explainability — EU AI Act Compliant */}
      <div style={{
        marginTop: '16px',
        padding: '16px',
        background: 'var(--bg-secondary, #111827)',
        borderRadius: '12px',
        border: '1px solid var(--border-primary, rgba(255,255,255,0.06))',
      }}>
        <ExplainabilityPanel
          threatId={selectedThreat?.incident_id}
          showAudienceToggle={true}
        />
      </div>
    </motion.div>
  );
}

export default ThreatsPage;
