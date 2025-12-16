import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
    plugins: [react()],
    resolve: {
        alias: {
            "@": path.resolve(process.cwd(), "./src"),
        },
    },
    build: {
        outDir: 'dist',
    },
    server: {
        host: '0.0.0.0',
        port: 5173,
    }
})
