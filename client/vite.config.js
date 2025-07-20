import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ],
  server: {
    proxy: {
      '/upload': 'http://127.0.0.1:5000',
      '/analyze': 'http://127.0.0.1:5000',
      '/report': 'http://127.0.0.1:5000',
      '/ask-ai': 'http://127.0.0.1:5000',
      
    }
  }
});
