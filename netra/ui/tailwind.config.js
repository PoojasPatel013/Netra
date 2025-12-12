/** @type {import('tailwindcss').Config} */
export default {
    darkMode: 'class',
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                radium: {
                    50: '#e0fbff',
                    100: '#bdf6ff',
                    200: '#8aefff',
                    300: '#46e6ff',
                    400: '#00d5ff',
                    500: '#00f3ff', // Primary Electric Cyan
                    600: '#008ba3',
                    700: '#006d82',
                    800: '#005a6b',
                    900: '#004a59',
                },
                cyber: {
                    black: '#050a14',     // Deepest background
                    dark: '#0b1221',      // Card background
                    border: '#1e293b',
                    glass: 'rgba(11, 18, 33, 0.7)',
                    text: '#e2e8f0',     // Off-white for readability
                    muted: '#94a3b8'
                }
            },
            fontFamily: {
                sans: ['Inter', 'sans-serif'],
                mono: ['Fira Code', 'monospace'],
                display: ['Orbitron', 'sans-serif'], 
            },
            animation: {
                'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                'spin-slow': 'spin 3s linear infinite',
                'float': 'float 6s ease-in-out infinite',
            },
            keyframes: {
                float: {
                    '0%, 100%': { transform: 'translateY(0)' },
                    '50%': { transform: 'translateY(-10px)' },
                }
            },
            boxShadow: {
                'neon': '0 0 5px #00f3ff, 0 0 10px rgba(0, 243, 255, 0.3)',
                'neon-strong': '0 0 10px #00f3ff, 0 0 20px rgba(0, 243, 255, 0.5)',
            }
        },
    },
    plugins: [],
}
