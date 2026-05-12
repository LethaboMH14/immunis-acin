// frontend/src/pages/CopilotPage.tsx
// AI Security Copilot — chat interface with 6 audience levels
// WHY: The copilot demonstrates IMMUNIS's ability to communicate security
// findings at different technical levels. A CISO gets executive summaries.
// A SOC analyst gets code-level details. Same data, different framing.

import React, { useState, useCallback, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Card } from '../components/common/Card';
import { Button } from '../components/common/Button';
import { Select } from '../components/common/Select';
import { Badge } from '../components/common/Badge';
import { useMutation } from '../hooks/useApi';
import { useAuth } from '../providers/AuthProvider';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  audience?: string;
  timestamp: number;
}

interface CopilotResponse {
  response: string;
  audience: string;
  references?: string[];
}

// ─── Constants ────────────────────────────────────────────────────────────────

const AUDIENCE_OPTIONS = [
  { value: 'soc_analyst', label: 'SOC Analyst' },
  { value: 'ir_lead', label: 'IR Lead' },
  { value: 'ciso', label: 'CISO' },
  { value: 'it_director', label: 'IT Director' },
  { value: 'finance', label: 'Finance' },
  { value: 'auditor', label: 'Auditor' },
];

const QUICK_ACTIONS = [
  { id: 'explain', label: 'Explain latest threat', prompt: 'Explain the most recent threat detected by IMMUNIS in detail.' },
  { id: 'posture', label: 'Security posture summary', prompt: 'Give me a summary of our current security posture.' },
  { id: 'recommend', label: 'Top recommendations', prompt: 'What are the top 3 security actions I should take right now?' },
  { id: 'compliance', label: 'Compliance status', prompt: 'What is our current compliance status across all frameworks?' },
];

let messageCounter = 0;

// ─── Component ────────────────────────────────────────────────────────────────

function CopilotPage() {
  const { user } = useAuth();
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [audience, setAudience] = useState(user?.role || 'ciso');
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const chatMutation = useMutation<
    { message: string; audience: string; context?: unknown },
    CopilotResponse
  >('/api/copilot/chat');

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const sendMessage = useCallback(
    async (content: string) => {
      if (!content.trim()) return;

      const userMsg: ChatMessage = {
        id: `msg-${++messageCounter}`,
        role: 'user',
        content: content.trim(),
        timestamp: Date.now(),
      };

      setMessages((prev) => [...prev, userMsg]);
      setInput('');

      const result = await chatMutation.mutate({
        message: content.trim(),
        audience,
      });

      if (result) {
        const assistantMsg: ChatMessage = {
          id: `msg-${++messageCounter}`,
          role: 'assistant',
          content: result.response,
          audience: result.audience,
          timestamp: Date.now(),
        };
        setMessages((prev) => [...prev, assistantMsg]);
      } else {
        const errorMsg: ChatMessage = {
          id: `msg-${++messageCounter}`,
          role: 'assistant',
          content: 'I apologise, but I was unable to process your request. Please try again or check that the backend is running.',
          timestamp: Date.now(),
        };
        setMessages((prev) => [...prev, errorMsg]);
      }
    },
    [audience, chatMutation]
  );

  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      sendMessage(input);
    },
    [input, sendMessage]
  );

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage(input);
      }
    },
    [input, sendMessage]
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col h-[calc(100vh-8rem)]"
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-4 flex-shrink-0">
        <div>
          <h2 className="text-lg font-semibold text-[var(--text-primary)]">
            Security Copilot
          </h2>
          <p className="text-sm text-[var(--text-muted)]">
            AI-powered security assistant — speaks 6 audience languages
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Select
            label="Speaking to"
            options={AUDIENCE_OPTIONS}
            value={audience}
            onChange={(e) => setAudience(e.target.value as any)}
            selectSize="sm"
          />
        </div>
      </div>

      {/* Messages area */}
      <Card variant="default" padding="none" className="flex-1 flex flex-col min-h-0">
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {/* Welcome message */}
          {messages.length === 0 && (
            <div className="flex flex-col items-center justify-center h-full text-center py-12">
              <div className="w-12 h-12 rounded-full bg-[var(--color-immune)]/10 flex items-center justify-center mb-4">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="text-[var(--color-immune)]">
                  <path d="M3 18l4-8 4 8M5 14h4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                  <circle cx="17" cy="10" r="4" stroke="currentColor" strokeWidth="1.5" />
                  <path d="M17 14v4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                </svg>
              </div>
              <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-1">
                IMMUNIS Security Copilot
              </h3>
              <p className="text-xs text-[var(--text-muted)] max-w-sm mb-6">
                Ask about threats, vulnerabilities, compliance, or request explanations
                tailored to your role. Currently speaking as: <strong>{AUDIENCE_OPTIONS.find(a => a.value === audience)?.label}</strong>
              </p>

              {/* Quick actions */}
              <div className="flex flex-wrap gap-2 justify-center">
                {QUICK_ACTIONS.map((action) => (
                  <Button
                    key={action.id}
                    variant="outline"
                    size="sm"
                    onClick={() => sendMessage(action.prompt)}
                  >
                    {action.label}
                  </Button>
                ))}
              </div>
            </div>
          )}

          {/* Chat messages */}
          <AnimatePresence initial={false}>
            {messages.map((msg) => (
              <motion.div
                key={msg.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.2 }}
                className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                <div
                  className={[
                    'max-w-[80%] rounded-xl px-4 py-3',
                    msg.role === 'user'
                      ? 'bg-[var(--color-immune)]/10 text-[var(--text-primary)]'
                      : 'bg-[var(--bg-tertiary)] text-[var(--text-secondary)]',
                  ].join(' ')}
                >
                  {/* Role indicator */}
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
                      {msg.role === 'user' ? 'You' : 'Copilot'}
                    </span>
                    {msg.audience && (
                      <Badge variant="neutral">{msg.audience}</Badge>
                    )}
                  </div>

                  {/* Content */}
                  <div className="text-sm leading-relaxed whitespace-pre-wrap">
                    {msg.content}
                  </div>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>

          {/* Loading indicator */}
          {chatMutation.isLoading && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="flex justify-start"
            >
              <div className="bg-[var(--bg-tertiary)] rounded-xl px-4 py-3">
                <div className="flex items-center gap-1.5">
                  <div className="w-1.5 h-1.5 rounded-full bg-[var(--color-immune)] animate-bounce" style={{ animationDelay: '0ms' }} />
                  <div className="w-1.5 h-1.5 rounded-full bg-[var(--color-immune)] animate-bounce" style={{ animationDelay: '150ms' }} />
                  <div className="w-1.5 h-1.5 rounded-full bg-[var(--color-immune)] animate-bounce" style={{ animationDelay: '300ms' }} />
                </div>
              </div>
            </motion.div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input bar */}
        <form
          onSubmit={handleSubmit}
          className="flex items-end gap-2 p-4 border-t border-[var(--border-subtle)]"
        >
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask about security, threats, compliance..."
            rows={1}
            className={[
              'flex-1 resize-none rounded-lg px-3 py-2.5 text-sm',
              'bg-[var(--bg-tertiary)] border border-[var(--border-primary)]',
              'text-[var(--text-primary)] placeholder:text-[var(--text-muted)]',
              'focus:outline-none focus:ring-2 focus:ring-[var(--color-immune)] focus:border-transparent',
              'max-h-32',
            ].join(' ')}
          />
          <Button
            type="submit"
            variant="primary"
            size="md"
            disabled={!input.trim() || chatMutation.isLoading}
            isLoading={chatMutation.isLoading}
          >
            Send
          </Button>
        </form>
      </Card>
    </motion.div>
  );
}

export default CopilotPage;
