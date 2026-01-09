/**
 * Attachment upload/download fast-path for Warden Worker (JS)
 *
 * This module implements:
 * - Attachment upload logic (zero-copy streaming to R2)
 * - Attachment download logic (zero-copy streaming from R2)
 * - JWT validation for attachment tokens (HMAC-SHA256) using Web Crypto API
 *
 * Route matching and URL parsing should be handled by `src/entry.js`.
 */

const JWT_EXPECTED_ALG = "HS256";
const JWT_VALIDATION_LEEWAY_SECS = 60;
const SIZE_LEEWAY_BYTES = 1024 * 1024; // 1 MiB

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.name = "HttpError";
    this.status = status;
  }
}

function jsonError(status, message) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function requireBucket(env) {
  const bucket = env.ATTACHMENTS_BUCKET;
  if (!bucket) {
    throw new HttpError(400, "Attachments are not enabled");
  }
  return bucket;
}

function requireDatabase(env) {
  const db = getDatabase(env);
  if (!db) {
    throw new HttpError(500, "Database not available");
  }
  return db;
}

// Cache CryptoKey derived from JWT_SECRET across requests.
// Cloudflare Workers keep module scope warm between requests, so this saves
// importKey cost on hot paths.
let JWT_KEY_CACHE = {
  secret: null,
  keyPromise: null,
};

async function getJwtHmacKey(secret) {
  if (!secret) {
    throw new HttpError(500, "JWT_SECRET not configured");
  }

  if (JWT_KEY_CACHE.secret === secret && JWT_KEY_CACHE.keyPromise) {
    return JWT_KEY_CACHE.keyPromise;
  }

  const keyPromise = crypto.subtle.importKey(
    "raw",
    TEXT_ENCODER.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  JWT_KEY_CACHE = { secret, keyPromise };
  return keyPromise;
}

function decodeJsonFromB64Url(b64Url) {
  try {
    return JSON.parse(TEXT_DECODER.decode(base64UrlDecode(b64Url)));
  } catch {
    throw new HttpError(401, "Invalid token");
  }
}

// JWT validation using Web Crypto API (no external dependencies)
async function verifyJwt(token, key) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new HttpError(401, "Invalid token");
  }

  const [headerB64, payloadB64, signatureB64] = parts;

  const header = decodeJsonFromB64Url(headerB64);

  if (!header || typeof header !== "object" || header.alg !== JWT_EXPECTED_ALG) {
    throw new HttpError(401, "Invalid token");
  }

  // Decode the signature (base64url to Uint8Array)
  const signature = base64UrlDecode(signatureB64);

  // Verify the signature
  const data = TEXT_ENCODER.encode(`${headerB64}.${payloadB64}`);
  const valid = await crypto.subtle.verify("HMAC", key, signature, data);

  if (!valid) {
    throw new HttpError(401, "Invalid token");
  }

  const payload = decodeJsonFromB64Url(payloadB64);

  if (!payload || typeof payload !== "object") {
    throw new HttpError(401, "Invalid token");
  }
  
  if (typeof payload.exp !== "number") {
    throw new HttpError(401, "Invalid token");
  }
  
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now - JWT_VALIDATION_LEEWAY_SECS) {
    throw new HttpError(401, "Token expired");
  }

  if (!payload.sub || typeof payload.sub !== "string") {
    throw new HttpError(401, "Invalid token");
  }

  return payload;
}

export function base64UrlDecode(str) {
  // Convert base64url to base64
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  // Add padding if needed
  while (base64.length % 4) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Generate ISO timestamp string
function nowString() {
  return new Date().toISOString();
}

// Resolve the D1 binding regardless of naming style
function getDatabase(env) {
  return (
    env["warden-db"] ||
    env.warden_db ||
    env.WARDEN_DB ||
    env.DB ||
    env.vault1
  );
}

// Helper to get env var with fallback
function getEnvVar(env, name, defaultValue = null) {
  try {
    const value = env[name];
    if (value && typeof value.toString === "function") {
      return value.toString();
    }
    return value || defaultValue;
  } catch {
    return defaultValue;
  }
}

// Get attachment size limits from env
function getAttachmentMaxBytes(env) {
  const value = getEnvVar(env, "ATTACHMENT_MAX_BYTES");
  if (!value) return null;
  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? null : parsed;
}

function getTotalLimitBytes(env) {
  const value = getEnvVar(env, "ATTACHMENT_TOTAL_LIMIT_KB");
  if (!value) return null;
  const kb = parseInt(value, 10);
  if (isNaN(kb)) return null;
  return kb * 1024;
}

// Get user's current attachment usage
async function getUserAttachmentUsage(db, userId, excludeAttachmentId) {
  const query = excludeAttachmentId
    ? `SELECT COALESCE(SUM(file_size), 0) as total FROM (
         SELECT a.file_size as file_size
         FROM attachments a
         JOIN ciphers c ON c.id = a.cipher_id
         WHERE c.user_id = ?1 AND a.id != ?2
         UNION ALL
         SELECT p.file_size as file_size
         FROM attachments_pending p
         JOIN ciphers c2 ON c2.id = p.cipher_id
         WHERE c2.user_id = ?1 AND p.id != ?2
       ) AS files`
    : `SELECT COALESCE(SUM(file_size), 0) as total FROM (
         SELECT a.file_size as file_size
         FROM attachments a
         JOIN ciphers c ON c.id = a.cipher_id
         WHERE c.user_id = ?1
         UNION ALL
         SELECT p.file_size as file_size
         FROM attachments_pending p
         JOIN ciphers c2 ON c2.id = p.cipher_id
         WHERE c2.user_id = ?1
       ) AS files`;

  const bindings = excludeAttachmentId ? [userId, excludeAttachmentId] : [userId];

  const result = await db.prepare(query).bind(...bindings).first();
  return result?.total || 0;
}

// Enforce attachment size limits
async function enforceLimits(db, env, userId, newSize, excludeAttachmentId) {
  if (newSize < 0) {
    throw new Error("Attachment size cannot be negative");
  }

  const maxBytes = getAttachmentMaxBytes(env);
  if (maxBytes !== null && newSize > maxBytes) {
    throw new Error("Attachment size exceeds limit");
  }

  const limitBytes = getTotalLimitBytes(env);
  if (limitBytes !== null) {
    const used = await getUserAttachmentUsage(db, userId, excludeAttachmentId);
    const newTotal = used + newSize;
    if (newTotal > limitBytes) {
      throw new Error("Attachment storage limit reached");
    }
  }
}

function validateSizeWithinDeclared(declaredSize, actualSize) {
  const maxSize = declaredSize + SIZE_LEEWAY_BYTES;
  const minSize = Math.max(0, declaredSize - SIZE_LEEWAY_BYTES);
  if (actualSize < minSize || actualSize > maxSize) {
    throw new Error(
      `Attachment size mismatch (expected within [${minSize}, ${maxSize}], got ${actualSize})`
    );
  }
}

function validateTokenClaimsMatch(claims, cipherId, attachmentId) {
  if (claims.cipher_id !== cipherId || claims.attachment_id !== attachmentId) {
    throw new HttpError(401, "Invalid token");
  }
}

async function getUserCipher(db, cipherId, userId) {
  return await db
    .prepare(
      "SELECT id, user_id, organization_id, deleted_at FROM ciphers WHERE id = ?1 AND user_id = ?2"
    )
    .bind(cipherId, userId)
    .first();
}

async function getPendingAttachment(db, attachmentId) {
  return await db
    .prepare(
      "SELECT id, cipher_id, file_name, file_size, akey, created_at, organization_id FROM attachments_pending WHERE id = ?1"
    )
    .bind(attachmentId)
    .first();
}

async function getAttachmentRow(db, attachmentId) {
  return await db
    .prepare("SELECT id, cipher_id FROM attachments WHERE id = ?1")
    .bind(attachmentId)
    .first();
}

function parseSingleRange(rangeHeader, size) {
  if (!rangeHeader) return null;
  const value = rangeHeader.trim();
  if (!value.startsWith("bytes=")) return null;

  const spec = value.slice("bytes=".length);
  // Multiple ranges not supported.
  if (spec.includes(",")) {
    throw new HttpError(416, "Invalid Range");
  }

  const [startStr, endStr] = spec.split("-");
  if (startStr === "" && endStr === "") {
    throw new HttpError(416, "Invalid Range");
  }

  let start;
  let end;

  // Suffix range: bytes=-N
  if (startStr === "") {
    const suffixLength = parseInt(endStr, 10);
    if (!Number.isFinite(suffixLength) || suffixLength <= 0) {
      throw new HttpError(416, "Invalid Range");
    }
    if (suffixLength >= size) {
      start = 0;
    } else {
      start = size - suffixLength;
    }
    end = size - 1;
  } else {
    start = parseInt(startStr, 10);
    if (!Number.isFinite(start) || start < 0) {
      throw new HttpError(416, "Invalid Range");
    }

    if (endStr === "") {
      end = size - 1;
    } else {
      end = parseInt(endStr, 10);
      if (!Number.isFinite(end) || end < 0) {
        throw new HttpError(416, "Invalid Range");
      }
    }
  }

  if (start >= size) {
    throw new HttpError(416, "Range Not Satisfiable");
  }

  if (end >= size) {
    end = size - 1;
  }

  if (end < start) {
    throw new HttpError(416, "Invalid Range");
  }

  return { start, end };
}

// Handle azure-upload with zero-copy streaming
export async function handleAzureUpload(request, env, cipherId, attachmentId, token) {
  try {
    const bucket = requireBucket(env);
    const db = requireDatabase(env);

    const secret = env.JWT_SECRET?.toString?.() || env.JWT_SECRET;
    const key = await getJwtHmacKey(secret);
    const claims = await verifyJwt(token, key);
    validateTokenClaimsMatch(claims, cipherId, attachmentId);

    const userId = claims.sub;

    const cipher = await getUserCipher(db, cipherId, userId);
    if (!cipher) {
      return jsonError(404, "Cipher not found");
    }

    if (cipher.organization_id) {
      return jsonError(400, "Organization attachments are not supported");
    }

    if (cipher.deleted_at) {
      return jsonError(400, "Cannot modify attachments for deleted cipher");
    }

    const pending = await getPendingAttachment(db, attachmentId);
    if (!pending) {
      return jsonError(404, "Attachment not found or already uploaded");
    }

    if (pending.cipher_id !== cipherId) {
      return jsonError(400, "Attachment does not belong to cipher");
    }

  // Content-Length is not always present for browser uploads; treat it as
  // optional and validate against declared size after upload.
    const contentLengthHeader = request.headers.get("Content-Length");
    const contentLength = contentLengthHeader
      ? parseInt(contentLengthHeader, 10)
      : null;
    if (contentLengthHeader && (isNaN(contentLength) || contentLength <= 0)) {
      return jsonError(400, "Invalid Content-Length header");
    }

  // Enforce limits before upload
    try {
      const declaredOrHeaderSize = contentLength ?? pending.file_size;
      await enforceLimits(db, env, userId, declaredOrHeaderSize, attachmentId);
    } catch (err) {
      return jsonError(400, err?.message || "Invalid request");
    }

  // Build R2 key
    const r2Key = `${cipherId}/${attachmentId}`;

  // Prepare R2 put options
    const putOptions = {};
    const contentType = request.headers.get("Content-Type");
    if (contentType) {
      putOptions.httpMetadata = { contentType };
    }

  // Upload to R2 directly using request.body (zero-copy streaming)
    let r2Object;
    try {
      r2Object = await bucket.put(r2Key, request.body, putOptions);
    } catch {
      try {
        await bucket.delete(r2Key);
      } catch {
        // Ignore cleanup errors
      }
      return jsonError(500, "Upload failed");
    }

    const uploadedSize = r2Object.size;

  // If Content-Length was provided, ensure it matches. Always validate within
  // declared size leeway (matches Rust behavior).
    try {
      if (contentLength !== null && uploadedSize !== contentLength) {
        throw new Error("Content-Length does not match uploaded size");
      }
      validateSizeWithinDeclared(pending.file_size, uploadedSize);
    } catch (err) {
      try {
        await bucket.delete(r2Key);
      } catch {
        // Ignore cleanup errors
      }
      return jsonError(400, err?.message || "Invalid request");
    }

  // Finalize upload: move pending -> attachments and touch revision timestamps
    const now = nowString();
    try {
      await db.batch([
        db
          .prepare(
            "INSERT INTO attachments (id, cipher_id, file_name, file_size, akey, created_at, updated_at, organization_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
          )
          .bind(
            attachmentId,
            cipherId,
            pending.file_name,
            uploadedSize,
            pending.akey,
            pending.created_at || now,
            now,
            pending.organization_id || null
          ),
        db.prepare("DELETE FROM attachments_pending WHERE id = ?1").bind(attachmentId),
        db
          .prepare("UPDATE ciphers SET updated_at = ?1 WHERE id = ?2")
          .bind(now, cipherId),
        db.prepare("UPDATE users SET updated_at = ?1 WHERE id = ?2").bind(now, userId),
      ]);
    } catch {
      try {
        await bucket.delete(r2Key);
      } catch {
        // Ignore cleanup errors
      }
      return jsonError(500, "Finalize failed");
    }

    return new Response(null, { status: 201 });
  } catch (err) {
    if (err instanceof HttpError) {
      return jsonError(err.status, err.message);
    }
    return jsonError(500, "Internal error");
  }
}

// Handle download with zero-copy streaming
export async function handleDownload(request, env, cipherId, attachmentId, token) {
  try {
    const bucket = requireBucket(env);
    const db = requireDatabase(env);

    const secret = env.JWT_SECRET?.toString?.() || env.JWT_SECRET;
    const key = await getJwtHmacKey(secret);
    const claims = await verifyJwt(token, key);
    validateTokenClaimsMatch(claims, cipherId, attachmentId);

    const userId = claims.sub;

    const cipher = await getUserCipher(db, cipherId, userId);
    if (!cipher) {
      return jsonError(404, "Cipher not found");
    }

    const attachment = await getAttachmentRow(db, attachmentId);
    if (!attachment) {
      return jsonError(404, "Attachment not found");
    }

    if (attachment.cipher_id !== cipherId) {
      return jsonError(400, "Attachment does not belong to cipher");
    }

    const r2Key = `${cipherId}/${attachmentId}`;

    // Fetch metadata first (needed for range handling and headers).
    const headObject = await bucket.head(r2Key);
    if (!headObject) {
      return jsonError(404, "Attachment not found in storage");
    }

    const size = headObject.size;
    const contentType = headObject.httpMetadata?.contentType || "application/octet-stream";

    const headers = new Headers();
    headers.set("Content-Type", contentType);
    headers.set("Accept-Ranges", "bytes");

    const rangeHeader = request.headers.get("Range");
    let range;
    try {
      range = parseSingleRange(rangeHeader, size);
    } catch (err) {
      if (err instanceof HttpError && err.status === 416) {
        headers.set("Content-Range", `bytes */${size}`);
        return new Response(null, { status: 416, headers });
      }
      throw err;
    }

    if (!range) {
      const r2Object = await bucket.get(r2Key);
      if (!r2Object) {
        return jsonError(404, "Attachment not found in storage");
      }
      headers.set("Content-Length", size.toString());
      return new Response(r2Object.body, { status: 200, headers });
    }

    const { start, end } = range;
    const length = end - start + 1;
    const r2Object = await bucket.get(r2Key, {
      range: { offset: start, length },
    });

    if (!r2Object) {
      return jsonError(404, "Attachment not found in storage");
    }

    headers.set("Content-Range", `bytes ${start}-${end}/${size}`);
    headers.set("Content-Length", length.toString());
    return new Response(r2Object.body, { status: 206, headers });
  } catch (err) {
    if (err instanceof HttpError) {
      return jsonError(err.status, err.message);
    }
    return jsonError(500, "Internal error");
  }
}