/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        nova: {
          orange: '#E8470A',
          'orange-light': '#FF5A1A',
          'orange-dark': '#C03A08',
          black: '#0F0F0F',
          dark: '#141414',
          slate: '#1C1C1E',
          border: '#2C2C2E',
          muted: '#8D8D8D',
          light: '#F5F5F5',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-orange': 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'spin-slow': 'spin 1.5s linear infinite',
      },
    },
  },
  plugins: [],
}
