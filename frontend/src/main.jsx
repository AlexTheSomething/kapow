import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.jsx';
import './index.css';

// Global error catcher: if anything throws during render, show the error
// text instead of a silent blank window.
class GlobalError extends React.Component {
  constructor(props) { super(props); this.state = { error: null }; }
  static getDerivedStateFromError(error) { return { error }; }
  componentDidCatch(error, info) { console.error('[Kapow GlobalError]', error, info); }
  render() {
    if (this.state.error) {
      return (
        <div style={{ padding: 24, fontFamily: 'monospace', color: '#fca5a5', background: '#0b0f19' }}>
          <h2 style={{ color: '#f43f5e' }}>Kapow crashed on load:</h2>
          <pre style={{ whiteSpace: 'pre-wrap', fontSize: 12 }}>{String(this.state.error.stack || this.state.error)}</pre>
        </div>
      );
    }
    return this.props.children;
  }
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <GlobalError>
      <App />
    </GlobalError>
  </React.StrictMode>
);
