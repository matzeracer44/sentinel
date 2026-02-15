/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/renderer/**/*.{js,jsx,ts,tsx}', './public/index.html'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Cyberpunk dark theme colors
        dark: {
          bg: '#0a0e27',
          surface: '#151b3d',
          elevated: '#1e2749',
          border: '#2d3659',
        },
        // Accent color options
        accent: {
          cyan: {
            DEFAULT: '#00d9ff',
            light: '#5ce1ff',
            dark: '#00a8cc',
          },
          purple: {
            DEFAULT: '#b026ff',
            light: '#d264ff',
            dark: '#8b1fd9',
          },
          red: {
            DEFAULT: '#ff2e63',
            light: '#ff5c87',
            dark: '#cc1f4a',
          },
          green: {
            DEFAULT: '#00ff88',
            light: '#5cffb4',
            dark: '#00cc6e',
          },
        },
        // Threat levels
        threat: {
          safe: '#00ff88',
          warning: '#ffd000',
          danger: '#ff2e63',
          critical: '#ff0055',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(0, 217, 255, 0.5)' },
          '100%': { boxShadow: '0 0 20px rgba(0, 217, 255, 0.8)' },
        },
      },
      backdropBlur: {
        xs: '2px',
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
    require('@tailwindcss/typography'),
  ],
};
