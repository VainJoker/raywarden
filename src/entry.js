import RustWorker from "../build/index.js";

// Cloudflare Module Worker entry point.
// For MVP we only pass through to the Rust/WASM worker.
export default {
  async fetch(request, env, ctx) {
    const worker = new RustWorker(ctx, env);
    return worker.fetch(request);
  },
};

