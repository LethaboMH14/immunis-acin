// frontend/src/providers/AuthProvider.tsx
// Authentication and role management for IMMUNIS ACIN
// WHY: The response layer formats output for 6 different audiences.
// The lockout system needs to know who is authenticated.
// Role switching lets judges see all 6 audience views in the demo.

import {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  type ReactNode,
} from 'react';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type UserRole =
  | 'soc_analyst'
  | 'ir_lead'
  | 'ciso'
  | 'it_director'
  | 'finance'
  | 'auditor';

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  avatar?: string;
}

interface AuthContextValue {
  /** Current authenticated user (null if not logged in) */
  user: User | null;
  /** Whether a user is authenticated */
  isAuthenticated: boolean;
  /** Log in with user data */
  login: (user: User) => void;
  /** Log out and clear session */
  logout: () => void;
  /** Switch to active audience role (for response layer formatting) */
  switchRole: (role: UserRole) => void;
  /** The currently active audience for response formatting */
  activeAudience: UserRole;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const AUTH_STORAGE_KEY = 'immunis-auth-user';
const AUDIENCE_STORAGE_KEY = 'immunis-active-audience';

const VALID_ROLES = new Set<string>([
  'soc_analyst',
  'ir_lead',
  'ciso',
  'it_director',
  'finance',
  'auditor',
]);

const DEFAULT_DEMO_USER: User = {
  id: 'demo-analyst-001',
  name: 'Demo Analyst',
  email: 'analyst@immunis.local',
  role: 'soc_analyst',
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getStoredUser(): User | null {
  try {
    const raw = localStorage.getItem(AUTH_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (
      typeof parsed.id === 'string' &&
      typeof parsed.name === 'string' &&
      typeof parsed.email === 'string' &&
      typeof parsed.role === 'string' &&
      VALID_ROLES.has(parsed.role)
    ) {
      return parsed as unknown as User;
    }
  } catch {
    // Corrupted or unavailable
  }
  return null;
}

function getStoredAudience(): UserRole {
  try {
    const stored = localStorage.getItem(AUDIENCE_STORAGE_KEY);
    if (stored && VALID_ROLES.has(stored)) return stored as UserRole;
  } catch {
    // Unavailable
  }
  return 'soc_analyst';
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

const AuthContext = createContext<AuthContextValue | null>(null);

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

interface AuthProviderProps {
  children: ReactNode;
  /** Skip auto-login for testing */
  disableAutoLogin?: boolean;
}

export function AuthProvider({
  children,
  disableAutoLogin = false,
}: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(() => {
    const stored = getStoredUser();
    if (stored) return stored;
    // Demo mode: auto-login
    if (!disableAutoLogin) return DEFAULT_DEMO_USER;
    return null;
  });

  const [activeAudience, setActiveAudience] = useState<UserRole>(
    () => getStoredAudience()
  );

  // Persist user to localStorage
  useEffect(() => {
    try {
      if (user) {
        localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(user));
      } else {
        localStorage.removeItem(AUTH_STORAGE_KEY);
      }
    } catch {
      // Silently fail
    }
  }, [user]);

  // Persist audience to localStorage
  useEffect(() => {
    try {
      localStorage.setItem(AUDIENCE_STORAGE_KEY, activeAudience);
    } catch {
      // Silently fail
    }
  }, [activeAudience]);

  const login = useCallback((u: User) => {
    setUser(u);
    setActiveAudience(u.role);
  }, []);

  const logout = useCallback(() => {
    setUser(null);
    setActiveAudience('soc_analyst');
    try {
      localStorage.removeItem(AUTH_STORAGE_KEY);
      localStorage.removeItem(AUDIENCE_STORAGE_KEY);
    } catch {
      // Silently fail
    }
  }, []);

  const switchRole = useCallback((role: UserRole) => {
    if (VALID_ROLES.has(role)) {
      setActiveAudience(role);
    }
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: user !== null,
        login,
        logout,
        switchRole,
        activeAudience,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}
