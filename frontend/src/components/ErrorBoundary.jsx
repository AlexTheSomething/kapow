import React from 'react';

// Minimal error boundary so runtime crashes render as readable text
// instead of a silent blank canvas.
export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // eslint-disable-next-line no-console
    console.error('[Kapow ErrorBoundary]', error, info);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="w-full h-full flex items-center justify-center p-6 bg-dark-950">
          <div className="max-w-lg rounded-xl border border-rose-500/40 bg-rose-500/10 p-4 text-rose-200 text-xs font-mono overflow-auto">
            <p className="font-bold text-rose-300 mb-2">Component crashed:</p>
            <pre className="whitespace-pre-wrap">{String(this.state.error && this.state.error.stack || this.state.error)}</pre>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
