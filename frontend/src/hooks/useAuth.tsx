// frontend/src/hooks/useAuth.tsx
import { createContext, useContext, useState, useCallback, ReactNode } from 'react';

export interface User {
  id: string;
  name: string;
  email: string;
  role: 'soc_analyst' | 'ir_lead' | 'ciso' | 'it_director' | 'finance' | 'auditor';
}

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isDemoMode: boolean;
  role: User['role'];
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  setRole: (role: User['role']) => void;
  switchRole: (role: User['role']) => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    // Return safe defaults instead of throwing - prevents crashes in demo
    return {
      user: { id: 'demo', name: 'Demo User', email: 'demo@immunis.acin', role: 'soc_analyst' },
      isAuthenticated: true,
      isDemoMode: true,
      role: 'soc_analyst',
      login: async () => {},
      logout: () => {},
      setRole: (_role: User['role']) => {},
      switchRole: (_role: User['role']) => {},
    };
  }
  return context;
}

export function AuthProvider({ children, autoDemo = true }: { children: ReactNode; autoDemo?: boolean }) {
  const [user, setUser] = useState<User | null>({
    id: 'demo-user',
    name: 'Demo User',
    email: 'demo@immunis.acin',
    role: 'soc_analyst',
  });
  const [isDemoMode, setIsDemoMode] = useState(autoDemo);
  const [role, setRoleState] = useState<User['role']>('soc_analyst');

  const login = useCallback(async (_email: string, _password: string) => {
    setUser({
      id: 'demo-user',
      name: 'Demo User',
      email: _email,
      role: 'soc_analyst',
    });
  }, []);

  const logout = useCallback(() => {
    setUser(null);
  }, []);

  const setRole = useCallback((newRole: User['role']) => {
    setRoleState(newRole);
    if (user) {
      setUser({ ...user, role: newRole });
    }
  }, [user]);

  const value: AuthContextType = {
    user,
    isAuthenticated: user !== null,
    isDemoMode,
    role,
    login,
    logout,
    setRole,
    switchRole: setRole,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}