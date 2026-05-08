// frontend/src/App.tsx
// Application root — DashboardLayout + PageRouter
// WHY: The original App.tsx was a monolithic dashboard built in Session 4.
// Now that we have proper layout components, providers, and a router,
// App.tsx becomes a thin wrapper that composes them.

import React from 'react';
import { DashboardLayout } from './components/layout/DashboardLayout';
import { PageRouter } from './router';

function App() {
  return (
    <DashboardLayout>
      {(activeRoute, navigate) => (
        <PageRouter activeRoute={activeRoute} onNavigate={navigate} />
      )}
    </DashboardLayout>
  );
}

export default App;
