/**
 * Safe secret redaction utility for MindVault MCP.
 *
 * Centralizes redaction for secret keys, API keys, payment headers, auth entries,
 * seed phrases, signed XDR, and bearer tokens to prevent accidental logging of
 * sensitive information across nested RPC payloads, diagnostics, and debug bundles.
 */

/**
 * Redaction patterns for common secret formats
 */
const SECRET_PATTERNS = [
  // Stellar secret keys (S followed by 55 base32 characters)
  /S[A-Z2-7]{55}/g,
  // 64-character hexadecimal private keys / seeds
  /\b[a-fA-F0-9]{64}\b/g,
  // BIP-39 mnemonic seed phrases (12-24 words, single or multiline)
  /(?:\b[a-z]{3,12}[\s\r\n]+){11,23}[a-z]{3,12}\b/gi,
  // Signed Stellar transaction envelopes (Base64 transaction envelopes)
  /\bAAAA[A-Za-z0-9+/=]{40,}\b/g,
  // Stripe-style / common sk_live / sk_test secrets
  /sk_(?:live|test)_[A-Za-z0-9]+/gi,
  // API keys (common patterns)
  /(?:api[_-]?key|apikey|secret[_-]?key|auth[_-]?token|access[_-]?token)[\s=:]+[A-Za-z0-9._-]{20,}/gi,
  // Bearer tokens
  /bearer\s+[A-Za-z0-9._-]{20,}/gi,
  // Authorization headers
  /authorization[\s=:]+[^\s]+/gi,
  // x-api-key headers
  /x-api-key[\s=:]+[^\s]+/gi,
  // Payment and signature headers
  /x-payment(?:-signature)?[\s=:]+[^\s]+/gi,
  /x-auth-token[\s=:]+[^\s]+/gi,
  // Generic long alphanumeric strings that look like secrets
  /\b[A-Za-z0-9]{32,}\b/g,
];

/**
 * Redact secrets from a string using common patterns.
 *
 * @param input - The string to redact secrets from
 * @returns The redacted string with secrets replaced by [REDACTED]
 */
export function redactSecrets(input: string): string {
  if (!input || typeof input !== "string") {
    return input;
  }

  let redacted = input;

  for (const pattern of SECRET_PATTERNS) {
    redacted = redacted.replace(pattern, "[REDACTED]");
  }

  return redacted;
}

/**
 * Redact secrets from an object recursively.
 * Handles nested errors, non-enumerable properties, and circular references.
 *
 * @param obj - The object to redact secrets from
 * @returns A new object with secrets redacted
 */
export function redactObject<T>(obj: T, seen = new WeakSet()): T {
  if (obj === null || obj === undefined) {
    return obj;
  }

  if (typeof obj === "string") {
    return redactSecrets(obj) as T;
  }

  if (typeof obj !== "object") {
    return obj;
  }

  if (seen.has(obj as object)) {
    return "[Circular]" as unknown as T;
  }
  seen.add(obj as object);

  if (Array.isArray(obj)) {
    return obj.map((item) => redactObject(item, seen)) as unknown as T;
  }

  if (obj instanceof Error) {
    const result: any = {
      name: redactSecrets(obj.name),
      message: redactSecrets(obj.message),
    };
    if (obj.stack) {
      result.stack = redactSecrets(obj.stack);
    }
    if ("cause" in obj && (obj as any).cause !== undefined) {
      result.cause = redactObject((obj as any).cause, seen);
    }
    for (const key of Object.getOwnPropertyNames(obj)) {
      if (key in result) continue;
      const val = (obj as any)[key];
      if (isSecretFieldName(key)) {
        result[key] = "[REDACTED]";
      } else {
        result[key] = redactObject(val, seen);
      }
    }
    return result as T;
  }

  const result: any = {};
  for (const [key, value] of Object.entries(obj as any)) {
    // Redact known secret field names
    if (isSecretFieldName(key)) {
      result[key] = "[REDACTED]";
    } else {
      result[key] = redactObject(value, seen);
    }
  }
  return result as T;
}

/**
 * Check if a field name is likely to contain a secret.
 *
 * Matching is substring-based on the lowercased field name, so the markers
 * below also cover camelCase and snake_case spellings (`secret` covers
 * `secretKey`/`secret_key`, `apikey` covers `apiKey`/`api_key`/`x-api-key`).
 */
function isSecretFieldName(fieldName: string): boolean {
  const secretFields = [
    "secret",
    "secretKey",
    "secret_key",
    "privateKey",
    "private_key",
    "seed",
    "mnemonic",
    "signature",
    "envelope",
    "xdr",
    "apiKey",
    "api_key",
    "apikey",
    "accessToken",
    "access_token",
    "authToken",
    "auth_token",
    "password",
    "token",
    "bearer",
    "authorization",
    "x-api-key",
    "xApiKey",
    "x-payment",
    "xpayment",
  ];

  const lowerName = fieldName.toLowerCase();
  return secretFields.some((field) => lowerName.includes(field.toLowerCase()));
}

/**
 * Safe error logging that redacts secrets from error messages and nested payloads.
 *
 * @param error - The error to log
 * @returns A safe error message with secrets redacted
 */
export function safeErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    let msg = redactSecrets(error.message);
    if ("data" in error && (error as any).data) {
      msg += ` data: ${safeLog((error as any).data)}`;
    }
    if ("cause" in error && (error as any).cause) {
      msg += ` cause: ${safeErrorMessage((error as any).cause)}`;
    }
    return redactSecrets(msg);
  }
  if (typeof error === "string") {
    return redactSecrets(error);
  }
  try {
    return redactSecrets(JSON.stringify(redactObject(error)));
  } catch {
    return redactSecrets(String(error));
  }
}

/**
 * Safe logging function that redacts secrets before output.
 *
 * @param data - The data to log safely
 * @returns A safe string representation with secrets redacted
 */
export function safeLog(data: unknown): string {
  try {
    const redacted = redactObject(data);
    return JSON.stringify(redacted, null, 2);
  } catch {
    return redactSecrets(String(data));
  }
}
