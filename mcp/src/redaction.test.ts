/**
 * Tests for the safe secret redaction utility
 */

import { describe, it, expect } from "vitest";
import { redactSecrets, redactObject, safeErrorMessage, safeLog } from "./redaction.js";

describe("redaction utility", () => {
  describe("redactSecrets", () => {
    it("should redact Stellar secret keys", () => {
      const input = "My secret key is SABCDEFGHIJKLMNOPQRSTUVWXYZ23456789 and other text";
      const result = redactSecrets(input);
      expect(result).toBe("My secret key is [REDACTED] and other text");
    });

    it("should redact API keys", () => {
      const input = "api_key=sk_live_1234567890abcdef";
      const result = redactSecrets(input);
      expect(result).toContain("[REDACTED]");
    });

    it("should redact bearer tokens", () => {
      const input = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
      const result = redactSecrets(input);
      expect(result).toContain("[REDACTED]");
    });

    it("should redact authorization headers", () => {
      const input = "authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=";
      const result = redactSecrets(input);
      expect(result).toContain("[REDACTED]");
    });

    it("should redact x-api-key headers", () => {
      const input = "x-api-key: sk_test_1234567890abcdef";
      const result = redactSecrets(input);
      expect(result).toContain("[REDACTED]");
    });

    it("should redact generic long alphanumeric strings", () => {
      const input = "token: ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdef";
      const result = redactSecrets(input);
      expect(result).toContain("[REDACTED]");
    });

    it("should not modify strings without secrets", () => {
      const input = "This is a normal string with no secrets";
      const result = redactSecrets(input);
      expect(result).toBe(input);
    });

    it("should handle empty strings", () => {
      const result = redactSecrets("");
      expect(result).toBe("");
    });

    it("should handle null and undefined", () => {
      expect(redactSecrets(null as any)).toBe(null);
      expect(redactSecrets(undefined as any)).toBe(undefined);
    });
  });

  describe("redactObject", () => {
    it("should redact secrets in objects", () => {
      const input = {
        name: "test",
        secretKey: "SABCDEFGHIJKLMNOPQRSTUVWXYZ23456789",
        apiKey: "sk_live_1234567890abcdef",
      };
      const result = redactObject(input);
      expect(result.secretKey).toBe("[REDACTED]");
      expect(result.apiKey).toBe("[REDACTED]");
      expect(result.name).toBe("test");
    });

    it("should redact secrets in nested objects", () => {
      const input = {
        user: {
          name: "test",
          credentials: {
            secretKey: "SABCDEFGHIJKLMNOPQRSTUVWXYZ23456789",
          },
        },
      };
      const result = redactObject(input);
      expect(result.user.credentials.secretKey).toBe("[REDACTED]");
      expect(result.user.name).toBe("test");
    });

    it("should redact secrets in arrays", () => {
      const input = [
        { name: "item1", secret: "secret123" },
        { name: "item2", secret: "secret456" },
      ];
      const result = redactObject(input);
      expect(result[0].secret).toBe("[REDACTED]");
      expect(result[1].secret).toBe("[REDACTED]");
    });

    it("should handle primitive types", () => {
      expect(redactObject(123)).toBe(123);
      expect(redactObject(true)).toBe(true);
      expect(redactObject("test")).toBe("test");
    });

    it("should handle null and undefined", () => {
      expect(redactObject(null)).toBe(null);
      expect(redactObject(undefined)).toBe(undefined);
    });
  });

  describe("safeErrorMessage", () => {
    it("should redact secrets from Error objects", () => {
      const error = new Error("Failed with secret SABCDEFGHIJKLMNOPQRSTUVWXYZ23456789");
      const result = safeErrorMessage(error);
      expect(result).toContain("[REDACTED]");
      expect(result).not.toContain("SABCDEFGHIJKLMNOPQRSTUVWXYZ23456789");
    });

    it("should handle string errors", () => {
      const result = safeErrorMessage("Error with secret sk_live_1234567890abcdef");
      expect(result).toContain("[REDACTED]");
    });

    it("should handle unknown types", () => {
      const result = safeErrorMessage({ secret: "test123" });
      expect(result).toContain("[REDACTED]");
    });
  });

  describe("safeLog", () => {
    it("should safely log objects with secrets", () => {
      const input = {
        user: "test",
        secretKey: "SABCDEFGHIJKLMNOPQRSTUVWXYZ23456789",
      };
      const result = safeLog(input);
      expect(result).toContain("[REDACTED]");
      expect(result).not.toContain("SABCDEFGHIJKLMNOPQRSTUVWXYZ23456789");
    });

    it("should safely log strings with secrets", () => {
      const result = safeLog("Secret: SABCDEFGHIJKLMNOPQRSTUVWXYZ23456789");
      expect(result).toContain("[REDACTED]");
    });

    it("should handle circular references gracefully", () => {
      const obj: any = { name: "test" };
      obj.self = obj;
      const result = safeLog(obj);
      // Should not throw and should contain redacted content if any
      expect(typeof result).toBe("string");
    });
  });

  describe("nested and multiline secret fixtures (#68)", () => {
    it("should redact single-line BIP-39 mnemonic seed phrases", () => {
      const phrase =
        "abandon ability able about above absent absorb abstract absurd abuse access accident";
      const input = `Wallet seed: ${phrase}`;
      expect(redactSecrets(input)).not.toContain("abandon");
      expect(redactSecrets(input)).toContain("[REDACTED]");
    });

    it("should redact multiline BIP-39 mnemonic seed phrases", () => {
      const multiline = `abandon ability able\nabout above absent\nabsorb abstract absurd\nabuse access accident`;
      const input = `Seed phrase:\n${multiline}`;
      expect(redactSecrets(input)).not.toContain("abandon");
      expect(redactSecrets(input)).toContain("[REDACTED]");
    });

    it("should redact 64-character hexadecimal private keys", () => {
      const hexKey = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
      const input = `private_key: ${hexKey}`;
      expect(redactSecrets(input)).not.toContain(hexKey);
      expect(redactSecrets(input)).toContain("[REDACTED]");
    });

    it("should redact signed Stellar transaction envelopes", () => {
      const signedXdr =
        "AAAAAGL2MDrt7b8Xp7Jp4b5V784G92k0L102948750192847501928374019283471029384710293847102938471029384=";
      const input = `Signed envelope: ${signedXdr}`;
      expect(redactSecrets(input)).not.toContain(signedXdr);
      expect(redactSecrets(input)).toContain("[REDACTED]");
    });

    it("should redact payment headers and auth tokens", () => {
      const input =
        "x-payment: eyJhbGciOi... and x-payment-signature: 1234567890abcdef1234567890abcdef";
      const result = redactSecrets(input);
      expect(result).not.toContain("eyJhbGciOi");
      expect(result).toContain("[REDACTED]");
    });

    it("should redact nested RPC error payloads and error causes", () => {
      const nestedErr: any = new Error("Soroban RPC transaction failed");
      nestedErr.data = {
        txHash: "1234",
        envelopeXdr:
          "AAAAAGL2MDrt7b8Xp7Jp4b5V784G92k0L102948750192847501928374019283471029384710293847102938471029384=",
        secretKey: "SBWYF2Z772WJ5ZODQ6S25H6QWFXKLL2Y5R7E6N3C425R2WFYG7R3H4E4",
      };
      nestedErr.cause = new Error(
        "Underlying error with key SBWYF2Z772WJ5ZODQ6S25H6QWFXKLL2Y5R7E6N3C425R2WFYG7R3H4E4",
      );

      const redacted = redactObject(nestedErr);
      expect(redacted.message).toBe("Soroban RPC transaction failed");
      expect(redacted.data.envelopeXdr).toBe("[REDACTED]");
      expect(redacted.data.secretKey).toBe("[REDACTED]");
      expect(redacted.cause.message).not.toContain("SBWYF2Z");
      expect(redacted.cause.message).toContain("[REDACTED]");

      const safeMsg = safeErrorMessage(nestedErr);
      expect(safeMsg).not.toContain("SBWYF2Z");
      expect(safeMsg).toContain("[REDACTED]");
    });
  });
});
