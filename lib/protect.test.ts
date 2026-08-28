import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import { protectText, analyzeText, mergeSpans } from "@/lib/protect";
import { decryptText, encryptText, sha256 } from "@/lib/crypto";
import { extractTextFromFile } from "@/lib/extract";

describe("protectText", () => {
  const sample = [
    "Contact Priya Shah at priya.shah@northwind.test or +1 312 555 0142.",
    "SSN 123-45-6789 and card 4111 1111 1111 1111 should never leak.",
    "Northwind Labs billed $12,400.00 on 04/18/2024.",
  ].join(" ");

  it("redacts two-word person names", () => {
    const result = protectText("From: Priya Shah <priya.shah@northwind.test>", {
      method: "redaction",
      entityTypes: ["PERSON", "EMAIL"],
      redactionLevel: "high",
      useNer: false,
    });
    expect(result.processed).not.toContain("Priya Shah");
    expect(result.processed).not.toContain("priya.shah@northwind.test");
  });

  it("redacts emails, phones, SSNs, and cards", () => {
    const result = protectText(sample, {
      method: "redaction",
      entityTypes: ["EMAIL", "PHONE", "SSN", "CREDIT_CARD"],
      redactionLevel: "high",
      useNer: false,
    });
    expect(result.processed).not.toMatch(/priya\.shah@northwind\.test/);
    expect(result.processed).not.toMatch(/123-45-6789/);
    expect(result.processed).not.toMatch(/4111 1111 1111 1111/);
    expect(result.processed).toContain("[REDACTED]");
    expect(result.counts.EMAIL).toBeGreaterThan(0);
    expect(result.counts.SSN).toBeGreaterThan(0);
  });

  it("keeps a readable prefix at low redaction", () => {
    const result = protectText("Write to ada@example.com today.", {
      method: "redaction",
      entityTypes: ["EMAIL"],
      redactionLevel: "low",
      useNer: false,
    });
    expect(result.processed).toContain("[REDACTED:ad...]");
  });

  it("masks emails with a synthetic address", () => {
    const result = protectText("Mail ada@example.com", {
      method: "masking",
      entityTypes: ["EMAIL"],
      useNer: false,
    });
    expect(result.processed).toMatch(/user\d+@masked\.example/);
    expect(result.processed).not.toContain("ada@example.com");
  });

  it("anonymizes the same value consistently", () => {
    const text = "ada@example.com and ada@example.com";
    const result = protectText(text, {
      method: "anonymization",
      entityTypes: ["EMAIL"],
      useNer: false,
    });
    const ids = result.processed.match(/[A-F0-9]{8}@anon\.example/g) ?? [];
    expect(ids).toHaveLength(2);
    expect(ids[0]).toBe(ids[1]);
  });

  it("redacts custom words", () => {
    const result = protectText("Project Kestrel is confidential.", {
      method: "redaction",
      entityTypes: [],
      customWords: ["Kestrel"],
      useNer: false,
    });
    expect(result.processed).toContain("[REDACTED]");
    expect(result.processed).not.toContain("Kestrel");
  });

  it("applies financial domain patterns", () => {
    const result = protectText("Wire 123456789012 to cover $9,100.00.", {
      method: "domain",
      entityTypes: [],
      domain: "financial",
      useNer: false,
    });
    expect(result.processed).not.toContain("123456789012");
    expect(result.processed).not.toContain("$9,100.00");
  });

  it("analyzes entity counts", () => {
    const counts = analyzeText("Email bob@site.test about 4111 1111 1111 1111");
    expect(counts.EMAIL).toBe(1);
    expect(counts.CREDIT_CARD).toBe(1);
  });
});

describe("mergeSpans", () => {
  it("drops overlapping weaker spans", () => {
    const merged = mergeSpans([
      { start: 0, end: 10, type: "PERSON", text: "aaaaaaaaaa" },
      { start: 2, end: 8, type: "EMAIL", text: "aaaaaa" },
    ]);
    expect(merged).toHaveLength(1);
    expect(merged[0].type).toBe("EMAIL");
  });
});

describe("crypto", () => {
  it("round-trips AES-GCM payloads", () => {
    const { key, ciphertext } = encryptText("secret dossier");
    expect(decryptText(ciphertext, key)).toBe("secret dossier");
  });

  it("hashes stably", () => {
    expect(sha256("abc")).toBe(sha256("abc"));
    expect(sha256("abc")).not.toBe(sha256("abd"));
  });
});

describe("extract", () => {
  it("reads plain text files", async () => {
    const text = await extractTextFromFile("notes.txt", Buffer.from("hello redact", "utf8"));
    expect(text).toBe("hello redact");
  });
});

describe("audit chain", () => {
  afterEach(() => {
    delete process.env.DATA_DIR;
  });

  it("appends a verifiable hash chain", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "redact-audit-"));
    process.env.DATA_DIR = dir;
    const { createUser } = await import("@/lib/db");
    const { appendAuditLog, verifyAuditChain } = await import("@/lib/audit");
    const user = createUser("tester", "tester@example.com", "password12");
    appendAuditLog({ userId: user.id, action: "redaction", dataHash: "aaa" });
    appendAuditLog({ userId: user.id, action: "masking", dataHash: "bbb" });
    const check = verifyAuditChain();
    expect(check.valid).toBe(true);
    expect(check.checked).toBe(2);
  });
});
