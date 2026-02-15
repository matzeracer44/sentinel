import React from 'react';
import { createRoot } from 'react-dom/client';
import { ErrorBoundary } from './components/ErrorBoundary';
import App from './App';
import './styles/global.css';

console.log('🚀 [Renderer] Initializing...');

const container = document.getElementById('root');
if (!container) {
  const err = 'Root element #root not found in DOM';
  console.error('❌ [Renderer] ' + err);
  throw new Error(err);
}

console.log('✅ [Renderer] Root container found');

try {
  console.log('✅ [Renderer] Creating React root...');
  const root = createRoot(container);
  
  console.log('✅ [Renderer] Rendering App...');
  root.render(
    <React.StrictMode>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </React.StrictMode>
  );
  
  console.log('✅ [Renderer] App rendered successfully');
} catch (error) {
  console.error('❌ [Renderer] FATAL ERROR:', error);
  document.body.innerHTML = `
    <div style="padding: 2rem; background: #1a1a1a; color: #fff; font-family: monospace;">
      <h1 style="color: #ff4444;">Fatal Error</h1>
      <pre>${error instanceof Error ? error.message + '\n\n' + error.stack : String(error)}</pre>
    </div>
  `;
}
