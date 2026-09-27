import { resolve } from "node:path";

// Use the existing backend toolchain for staging without installing or linking dependencies.
const backend = process.env.RAZIEL_BACKEND_ROOT;

export default {
  cacheDir: ".cache/vite",
  resolve: {
    alias: backend
      ? { vitest: resolve(backend, "packages/sdk-ts/node_modules/vitest/dist/index.js") }
      : {},
  },
  test: { include: ["test/**/*.test.ts"] },
};
