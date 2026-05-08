// frontend/src/pages/SettingsPage.tsx
// Settings — appearance, account, providers, notifications, about
// WHY: Judges may want to switch themes, change roles to see different
// audience views, or check which AI providers are active.

import React from 'react';
import { motion } from 'framer-motion';
import { Card } from '../components/common/Card';
import { Select } from '../components/common/Select';
import { Toggle } from '../components/common/Toggle';
import { Badge } from '../components/common/Badge';
import { useTheme } from '../providers/ThemeProvider';
import { useAuth } from '../providers/AuthProvider';
import { useLocalStorage } from '../hooks/useLocalStorage';

// ─── Types ────────────────────────────────────────────────────────────────────

interface NotificationPrefs {
  threats: boolean;
  antibodies: boolean;
  mesh: boolean;
  scans: boolean;
  compliance: boolean;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const THEME_OPTIONS = [
  { value: 'midnight', label: 'Midnight (Deep Dark)' },
  { value: 'twilight', label: 'Twilight (Medium)' },
  { value: 'overcast', label: 'Overcast (Light)' },
];

const DENSITY_OPTIONS = [
  { value: 'compact', label: 'Compact' },
  { value: 'comfortable', label: 'Comfortable' },
  { value: 'spacious', label: 'Spacious' },
];

const ROLE_OPTIONS = [
  { value: 'soc_analyst', label: 'SOC Analyst' },
  { value: 'ir_lead', label: 'IR Lead' },
  { value: 'ciso', label: 'CISO' },
  { value: 'it_director', label: 'IT Director' },
  { value: 'finance', label: 'Finance' },
  { value: 'auditor', label: 'Auditor' },
  { value: 'admin', label: 'Admin' },
];

// ─── Section Component ────────────────────────────────────────────────────────

function SettingsSection({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <Card padding="lg">
      <div className="mb-4">
        <h3 className="text-sm font-semibold text-[var(--text-primary)]">{title}</h3>
        {description && (
          <p className="text-xs text-[var(--text-muted)] mt-0.5">{description}</p>
        )}
      </div>
      <div className="space-y-4">{children}</div>
    </Card>
  );
}

function SettingsRow({
  label,
  description,
  children,
}: {
  label: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between py-2">
      <div>
        <p className="text-sm text-[var(--text-primary)]">{label}</p>
        {description && (
          <p className="text-xs text-[var(--text-muted)] mt-0.5">{description}</p>
        )}
      </div>
      <div className="flex-shrink-0">{children}</div>
    </div>
  );
}

// ─── Component ────────────────────────────────────────────────────────────────

function SettingsPage() {
  const { theme, density, setTheme, setDensity } = useTheme();
  const { user, setRole, isDemoMode } = useAuth();
  const [notifications, setNotifications] = useLocalStorage<NotificationPrefs>(
    'immunis-notifications',
    { threats: true, antibodies: true, mesh: true, scans: true, compliance: false }
  );

  const updateNotification = (key: keyof NotificationPrefs, value: boolean) => {
    setNotifications((prev) => ({ ...prev, [key]: value }));
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="max-w-2xl space-y-6"
    >
      <div>
        <h2 className="text-lg font-semibold text-[var(--text-primary)]">Settings</h2>
        <p className="text-sm text-[var(--text-muted)]">Configure appearance, account, and preferences</p>
      </div>

      {/* Appearance */}
      <SettingsSection title="Appearance" description="Customise the visual experience">
        <SettingsRow label="Theme" description="Color mode for the interface">
          <Select
            options={THEME_OPTIONS}
            value={theme}
            onChange={(e) => setTheme(e.target.value as any)}
            selectSize="sm"
          />
        </SettingsRow>
        <SettingsRow label="Density" description="Spacing between elements">
          <Select
            options={DENSITY_OPTIONS}
            value={density}
            onChange={(e) => setDensity(e.target.value as any)}
            selectSize="sm"
          />
        </SettingsRow>
      </SettingsSection>

      {/* Account */}
      <SettingsSection title="Account" description="User profile and role">
        <SettingsRow label="Name">
          <span className="text-sm text-[var(--text-primary)]">{user?.name ?? '—'}</span>
        </SettingsRow>
        <SettingsRow label="Email">
          <span className="text-sm text-[var(--text-muted)]">{user?.email ?? '—'}</span>
        </SettingsRow>
        <SettingsRow label="Role" description="Changes copilot audience and response detail level">
          <Select
            options={ROLE_OPTIONS}
            value={user?.role ?? 'ciso'}
            onChange={(e) => setRole(e.target.value as any)}
            selectSize="sm"
          />
        </SettingsRow>
        {isDemoMode && (
          <div className="pt-2">
            <Badge variant="warning">Demo Mode Active</Badge>
          </div>
        )}
      </SettingsSection>

      {/* Notifications */}
      <SettingsSection title="Notifications" description="Control toast notifications">
        <SettingsRow label="Threat detections">
          <Toggle
            checked={notifications.threats}
            onChange={(v) => updateNotification('threats', v)}
            size="sm"
          />
        </SettingsRow>
        <SettingsRow label="Antibody synthesis">
          <Toggle
            checked={notifications.antibodies}
            onChange={(v) => updateNotification('antibodies', v)}
            size="sm"
          />
        </SettingsRow>
        <SettingsRow label="Mesh broadcasts">
          <Toggle
            checked={notifications.mesh}
            onChange={(v) => updateNotification('mesh', v)}
            size="sm"
          />
        </SettingsRow>
        <SettingsRow label="Scan results">
          <Toggle
            checked={notifications.scans}
            onChange={(v) => updateNotification('scans', v)}
            size="sm"
          />
        </SettingsRow>
        <SettingsRow label="Compliance alerts">
          <Toggle
            checked={notifications.compliance}
            onChange={(v) => updateNotification('compliance', v)}
            size="sm"
          />
        </SettingsRow>
      </SettingsSection>

      {/* About */}
      <SettingsSection title="About IMMUNIS ACIN">
        <SettingsRow label="Version">
          <span className="text-xs font-mono text-[var(--text-muted)]">1.0.0-hackathon</span>
        </SettingsRow>
        <SettingsRow label="Build">
          <span className="text-xs font-mono text-[var(--text-muted)]">2025.05.09</span>
        </SettingsRow>
        <SettingsRow label="Backend">
          <span className="text-xs font-mono text-[var(--text-muted)]">55+ files · ~20K LOC</span>
        </SettingsRow>
        <SettingsRow label="Frontend">
          <span className="text-xs font-mono text-[var(--text-muted)]">~80 files · ~10K LOC</span>
        </SettingsRow>
        <SettingsRow label="Hackathon">
          <Badge variant="immune">AMD Developer Hackathon 2025</Badge>
        </SettingsRow>
        <div className="pt-3 border-t border-[var(--border-subtle)]">
          <p className="text-xs text-[var(--text-muted)] italic">
            "The breach that teaches. The system that remembers."
          </p>
        </div>
      </SettingsSection>
    </motion.div>
  );
}

export default SettingsPage;
