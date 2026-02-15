import React, { Component, ErrorInfo, ReactNode } from 'react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('❌ REACT ERROR BOUNDARY CAUGHT:', error);
    console.error('Component stack:', errorInfo.componentStack);
    
    // Send to main process for logging (best-effort, system.logError may not exist on ElectronAPI)
    try {
      const api = window.electronAPI as unknown as Record<string, Record<string, Function> | undefined> | undefined;
      if (typeof api?.system?.logError === 'function') {
        api.system.logError({
          type: 'REACT_ERROR',
          message: error.message,
          stack: error.stack,
          componentStack: errorInfo.componentStack,
        });
      }
    } catch {
      // Silently ignore — error boundary must never throw
    }
  }

  public render() {
    if (this.state.hasError) {
      return this.props.fallback || (
        <div style={{
          padding: '2rem',
          background: '#1a1a1a',
          color: '#fff',
          fontFamily: 'monospace',
          height: '100vh',
          overflow: 'auto'
        }}>
          <h1 style={{ color: '#ff4444' }}>⚠️ Sentinel Error</h1>
          <h2>Something went wrong</h2>
          <details style={{ marginTop: '1rem' }}>
            <summary style={{ cursor: 'pointer', color: '#4499ff' }}>
              Show Error Details
            </summary>
            <pre style={{ 
              background: '#000', 
              padding: '1rem', 
              borderRadius: '8px',
              overflow: 'auto',
              marginTop: '1rem'
            }}>
              {this.state.error?.message}
              {'\n\n'}
              {this.state.error?.stack}
            </pre>
          </details>
          <button 
            onClick={() => window.location.reload()}
            style={{
              marginTop: '1rem',
              padding: '0.5rem 1rem',
              background: '#4499ff',
              color: '#fff',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer'
            }}
          >
            Reload App
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
