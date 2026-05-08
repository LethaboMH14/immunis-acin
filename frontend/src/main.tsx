// frontend/src/main.tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { ThemeProvider } from './providers/ThemeProvider';
import { AuthProvider } from './providers/AuthProvider';
import { WebSocketProvider } from './providers/WebSocketProvider';
import './styles/globals.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ThemeProvider>
      <AuthProvider autoDemo={true}>
        <WebSocketProvider>
          <App />
        </WebSocketProvider>
      </AuthProvider>
    </ThemeProvider>
  </React.StrictMode>
);
