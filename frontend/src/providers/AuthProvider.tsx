// frontend/src/providers/AuthProvider.tsx
// Re-export from hooks to maintain backward compatibility
// WHY: Main auth implementation is now in hooks/useAuth.tsx

export { AuthProvider, useAuth } from '../hooks/useAuth';
export type { User } from '../hooks/useAuth';
