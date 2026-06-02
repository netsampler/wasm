import { resolve } from "node:path";
import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  base: process.env.VITE_BASE_PATH || "/",
  plugins: [vue()],
  cacheDir: "/private/tmp/flows-wasm-vite-cache",
  optimizeDeps: {
    exclude: ["wireview"],
  },
  build: {
    rollupOptions: {
      input: {
        main: resolve(import.meta.dirname, "index.html"),
        wireview: resolve(import.meta.dirname, "wireview.html"),
      },
    },
  },
});
