/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        dark: {
          950: '#070a13',
          900: '#0b0f19',
          850: '#0f172a',
          800: '#1e293b',
          700: '#334155',
          600: '#475569',
        },
        brand: {
          cyan: '#06b6d4',
          neon: '#00f2ff',
          indigo: '#6366f1',
          emerald: '#10b981',
          amber: '#f59e0b',
          rose: '#f43f5e',
        }
      },
      fontFamily: {
        sans: ['Inter', 'Outfit', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        'glow-cyan': '0 0 20px -3px rgba(6, 182, 212, 0.35)',
        'glow-emerald': '0 0 20px -3px rgba(16, 185, 129, 0.35)',
        'glow-indigo': '0 0 20px -3px rgba(99, 102, 241, 0.35)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in': 'fadeIn 0.4s ease-out both',
        'fade-in-slow': 'fadeIn 0.8s ease-out both',
        'slide-up': 'slideUp 0.25s cubic-bezier(0.16, 1, 0.3, 1) both',
        'slide-right': 'slideRight 0.25s cubic-bezier(0.16, 1, 0.3, 1) both',
        'slide-left': 'slideLeft 0.25s cubic-bezier(0.16, 1, 0.3, 1) both',
        'host-glow': 'hostGlow 0.9s ease-out both',
        'tag-pop': 'tagPop 0.45s cubic-bezier(0.34, 1.56, 0.64, 1) both',
        'scan-wave': 'scanWave 2.2s ease-in-out infinite',
        'shimmer': 'shimmer 1.8s linear infinite',
        'drill-zoom': 'drillZoom 0.35s cubic-bezier(0.22, 1, 0.36, 1) both',
        'pulse-ring': 'pulseRing 1.6s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(16px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideRight: {
          '0%': { opacity: '0', transform: 'translateX(24px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        slideLeft: {
          '0%': { opacity: '0', transform: 'translateX(-24px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        hostGlow: {
          '0%': { opacity: '0', transform: 'scale(0.3)', filter: 'brightness(3)' },
          '60%': { opacity: '1', transform: 'scale(1.15)', filter: 'brightness(1.6)' },
          '100%': { opacity: '1', transform: 'scale(1)', filter: 'brightness(1)' },
        },
        tagPop: {
          '0%': { opacity: '0', transform: 'scale(0.5)' },
          '70%': { opacity: '1', transform: 'scale(1.12)' },
          '100%': { opacity: '1', transform: 'scale(1)' },
        },
        scanWave: {
          '0%, 100%': { boxShadow: '0 0 0 0 rgba(6, 182, 212, 0.0)' },
          '50%': { boxShadow: '0 0 24px 2px rgba(6, 182, 212, 0.35)' },
        },
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
        drillZoom: {
          '0%': { opacity: '0', transform: 'scale(0.94)' },
          '100%': { opacity: '1', transform: 'scale(1)' },
        },
        pulseRing: {
          '0%': { transform: 'scale(0.8)', opacity: '0.7' },
          '80%, 100%': { transform: 'scale(2.2)', opacity: '0' },
        },
      }
    },
  },
  plugins: [],
}
