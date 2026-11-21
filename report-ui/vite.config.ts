import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';

// One IIFE script and one stylesheet. report_template.py inlines both into
// every report, so the reports stay single-file and work offline. Fonts and
// icons are inlined as data URIs for the same reason.
export const OUT_DIR = fileURLToPath(
  new URL('../aiml-security-assessment/functions/security/generate_consolidated_report/report_ui', import.meta.url)
);

export default defineConfig({
  plugins: [react()],
  define: { 'process.env.NODE_ENV': JSON.stringify('production') },
  build: {
    outDir: OUT_DIR,
    emptyOutDir: true,
    assetsInlineLimit: 100_000_000,
    cssCodeSplit: false,
    sourcemap: false,
    target: 'es2020',
    // Keep Cloudscape's modern selectors as written; lowering them for old
    // browsers expands the stylesheet several times over.
    cssTarget: ['chrome111', 'edge111', 'firefox114', 'safari16.4'],
    lib: {
      entry: fileURLToPath(new URL('./src/main.tsx', import.meta.url)),
      name: 'AimlSecurityReport',
      formats: ['iife'],
      fileName: () => 'report-ui.js',
      cssFileName: 'report-ui',
    },
  },
});
