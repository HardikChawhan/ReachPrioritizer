/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        ink: {
          950: '#030403',
          900: '#070907',
          850: '#0b0e0b',
          800: '#101410',
          700: '#171c17',
          600: '#222822',
        },
        lime: {
          DEFAULT: '#B4FF39',
          50: '#F4FFE3',
          200: '#DCFF9E',
          300: '#C8FF6B',
          400: '#B4FF39',
          500: '#9BE81E',
          600: '#76B80F',
          glow: 'rgba(180,255,57,0.35)',
        },
        fog: {
          50: '#F3F5F1',
          100: '#E3E7E0',
          300: '#B6BDB2',
          400: '#8D958A',
          500: '#687066',
          600: '#4A5148',
          700: '#323831',
        },
        risk: {
          critical: '#FF4D5E',
          high: '#FF9442',
          medium: '#FFD54A',
          low: '#7FA0B8',
        },
      },
      fontFamily: {
        display: ['"Space Grotesk Variable"', 'Inter Variable', 'system-ui', 'sans-serif'],
        sans: ['"Inter Variable"', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono Variable"', 'ui-monospace', 'monospace'],
      },
      boxShadow: {
        glow: '0 0 0 1px rgba(180,255,57,0.25), 0 0 40px -8px rgba(180,255,57,0.45)',
        'glow-sm': '0 0 24px -6px rgba(180,255,57,0.55)',
        'glow-red': '0 0 32px -6px rgba(255,77,94,0.6)',
        card: '0 1px 0 0 rgba(255,255,255,0.04) inset, 0 20px 60px -30px rgba(0,0,0,0.8)',
      },
      keyframes: {
        'fade-up': { '0%': { opacity: 0, transform: 'translateY(14px)' }, '100%': { opacity: 1, transform: 'translateY(0)' } },
        'pulse-ring': { '0%': { transform: 'scale(0.9)', opacity: 0.8 }, '100%': { transform: 'scale(2.2)', opacity: 0 } },
        dash: { to: { strokeDashoffset: '-24' } },
        shimmer: { '0%': { backgroundPosition: '-200% 0' }, '100%': { backgroundPosition: '200% 0' } },
        float: { '0%,100%': { transform: 'translateY(0)' }, '50%': { transform: 'translateY(-6px)' } },
      },
      animation: {
        'fade-up': 'fade-up 0.6s cubic-bezier(0.22,1,0.36,1) both',
        'pulse-ring': 'pulse-ring 1.8s cubic-bezier(0.22,1,0.36,1) infinite',
        dash: 'dash 1s linear infinite',
        shimmer: 'shimmer 2.2s linear infinite',
        float: 'float 6s ease-in-out infinite',
      },
    },
  },
  plugins: [],
}
