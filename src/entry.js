import RustWorker from "../build/index.js";
import {
  handleAzureUpload,
  handleDownload,
} from "./attchments.js";

const AZURE_UPLOAD_RE =
  /^\/api\/ciphers\/([^/]+)\/attachment\/([^/]+)\/azure-upload$/;
const DOWNLOAD_RE =
  /^\/api\/ciphers\/([^/]+)\/attachment\/([^/]+)\/download$/;

// Apply permissive CORS headers for attachment endpoints
function withCors(request, response) {
  const headers = new Headers(response.headers || {});

  const origin = request.headers.get("Origin");
  if (origin) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.append("Vary", "Origin");
  } else {
    headers.set("Access-Control-Allow-Origin", "*");
  }

  headers.set("Access-Control-Allow-Methods", "GET,PUT,OPTIONS");

  // Echo requested headers for preflight, plus a safe baseline.
  // Bitwarden clients (and some browsers) may send Azure-style headers like
  // `x-ms-blob-type`.
  const requested = request.headers.get("Access-Control-Request-Headers");
  const baseline = [
    "authorization",
    "content-type",
    "content-length",
    "accept",
    "origin",
    "user-agent",
    "x-ms-blob-type",
    "x-ms-date",
    "x-ms-version",
    "x-ms-client-request-id",
    "x-ms-return-client-request-id",
    "x-requested-with",
  ];
  const allowHeaders = requested
    ? `${requested},${baseline.join(",")}`
    : baseline.join(",");
  headers.set("Access-Control-Allow-Headers", allowHeaders);

  // Attachments use token-in-query, so credentials are typically not needed.
  // Avoid invalid combination: Allow-Credentials=true with Allow-Origin=*.
  if (origin) {
    headers.set("Access-Control-Allow-Credentials", "true");
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

// Preflight response helper
function preflight() {
  // The caller wraps with CORS using the incoming request.
  return new Response(null, { status: 204 });
}

async function dispatchAttachmentRoute({
  request,
  env,
  url,
  match,
  expectedMethod,
  handler,
}) {
  if (request.method === "OPTIONS") {
    return withCors(request, preflight());
  }
  if (request.method !== expectedMethod) {
    return withCors(request, new Response(null, { status: 405 }));
  }

  const [, cipherId, attachmentId] = match;
  const token = url.searchParams.get("token");
  if (!token) {
    return withCors(
      request,
      new Response(JSON.stringify({ error: "Missing token" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      })
    );
  }

  const resp = await handler(request, env, cipherId, attachmentId, token);
  return withCors(request, resp);
}

// Cloudflare Module Worker entry point.
// For MVP we only pass through to the Rust/WASM worker.
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    const azureMatch = pathname.match(AZURE_UPLOAD_RE);
    if (azureMatch) {
      return dispatchAttachmentRoute({
        request,
        env,
        url,
        match: azureMatch,
        expectedMethod: "PUT",
        handler: handleAzureUpload,
      });
    }

    const downloadMatch = pathname.match(DOWNLOAD_RE);
    if (downloadMatch) {
      return dispatchAttachmentRoute({
        request,
        env,
        url,
        match: downloadMatch,
        expectedMethod: "GET",
        handler: handleDownload,
      });
    }

    const worker = new RustWorker(ctx, env);
    return worker.fetch(request);
  },
};

