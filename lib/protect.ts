import nlp from "compromise";
import type {
  DetectedSpan,
  Domain,
  EntityType,
  ProtectOptions,
  ProtectResult,
  RedactionLevel,
} from "@/lib/types";
import { sha256 } from "@/lib/crypto";

const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/g;
const PHONE_RE =
  /\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/g;
const CARD_RE = /\b(?:\d{4}[ -]?){3}\d{4}\b/g;
const MONEY_RE = /(?:USD|INR|EUR|GBP|\$|£|€|₹)\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?\b/g;

const DOMAIN_PATTERNS: Record<Domain, Array<{ type: EntityType; pattern: RegExp }>> = {
  general: [
    { type: "BANK_ACCOUNT", pattern: /\b\d{10,16}\b/g },
    { type: "CREDIT_CARD", pattern: CARD_RE },
    { type: "SSN", pattern: SSN_RE },
    { type: "DATE", pattern: /\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b/g },
  ],
  financial: [
    { type: "MONEY", pattern: MONEY_RE },
    { type: "CREDIT_CARD", pattern: CARD_RE },
    { type: "BANK_ACCOUNT", pattern: /\b\d{10,16}\b/g },
  ],
  personal: [
    { type: "PHONE", pattern: PHONE_RE },
    { type: "EMAIL", pattern: EMAIL_RE },
    { type: "DATE", pattern: /\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s\d{1,2},?\s\d{4})\b/gi },
  ],
  health: [
    { type: "CUSTOM", pattern: /\bMR-\d{6,8}\b/g },
    { type: "CUSTOM", pattern: /\bPID-\d{6,10}\b/g },
    { type: "CUSTOM", pattern: /\bINS-\d{8,12}\b/g },
  ],
};

const MASK_POOLS: Record<string, string[]> = {
  PERSON: ["Ravi Menon", "Priya Shah", "Elena Varga", "Noah Okonkwo"],
  ORG: ["Northwind Labs", "Cedar & Pine Co", "Harborline Trust", "Kitefield Group"],
  GPE: ["Cedar Falls", "Port Enfield", "Lake Meridian", "Fort Sable"],
  LOC: ["North Quay", "Ridge Hollow", "East Wharf", "Old Mill Road"],
  DATE: ["12 Jan 2000", "03 Mar 1998", "21 Sep 2011", "08 Jun 2004"],
  EMAIL: ["masked.user@example.net", "redacted.contact@example.net"],
  PHONE: ["+1 312 555 0142", "+1 415 555 0198", "+1 206 555 0133"],
  SSN: ["000-00-0000"],
  CREDIT_CARD: ["4111 1111 1111 1111"],
  BANK_ACCOUNT: ["000000000000"],
  MONEY: ["$0.00"],
  CUSTOM: ["XXXX"],
};

function pushRegexSpans(
  text: string,
  regex: RegExp,
  type: EntityType,
  into: DetectedSpan[],
) {
  const flags = regex.flags.includes("g") ? regex.flags : `${regex.flags}g`;
  const re = new RegExp(regex.source, flags);
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    into.push({
      start: match.index,
      end: match.index + match[0].length,
      type,
      text: match[0],
    });
    if (match[0].length === 0) re.lastIndex += 1;
  }
}

function compromiseSpans(text: string, types: Set<EntityType>): DetectedSpan[] {
  const doc = nlp(text);
  const spans: DetectedSpan[] = [];

  const collect = (view: { json: (opts: { offset: true }) => Array<{ text?: string; offset?: { start: number; length: number } }> }, type: EntityType) => {
    if (!types.has(type)) return;
    for (const item of view.json({ offset: true })) {
      const start = item.offset?.start;
      const length = item.offset?.length;
      const value = item.text?.trim();
      if (start == null || !length || !value) continue;
      spans.push({ start, end: start + length, type, text: text.slice(start, start + length) });
    }
  };

  collect(doc.people(), "PERSON");
  collect(doc.organizations(), "ORG");
  collect(doc.places(), "GPE");
  return spans;
}

function priority(type: EntityType): number {
  switch (type) {
    case "EMAIL":
    case "SSN":
    case "CREDIT_CARD":
    case "PHONE":
    case "BANK_ACCOUNT":
      return 5;
    case "CUSTOM":
      return 4;
    case "PERSON":
    case "ORG":
      return 3;
    default:
      return 2;
  }
}

export function mergeSpans(spans: DetectedSpan[]): DetectedSpan[] {
  const sorted = [...spans].sort((a, b) => a.start - b.start || b.end - a.end || priority(b.type) - priority(a.type));
  const out: DetectedSpan[] = [];
  for (const span of sorted) {
    if (span.end <= span.start) continue;
    const last = out[out.length - 1];
    if (!last || span.start >= last.end) {
      out.push({ ...span });
      continue;
    }
    if (priority(span.type) > priority(last.type) || (priority(span.type) === priority(last.type) && span.end - span.start > last.end - last.start)) {
      out[out.length - 1] = span;
    }
  }
  return out;
}

function redactToken(text: string, level: RedactionLevel): string {
  if (level === "high") return "[REDACTED]";
  if (level === "medium") return `[REDACTED:${text.length}]`;
  const prefix = text.slice(0, Math.min(2, text.length));
  return `[REDACTED:${prefix}...]`;
}

function maskToken(span: DetectedSpan, index: number): string {
  if (span.type === "EMAIL") {
    return `user${1000 + (index % 9000)}@masked.example`;
  }
  const pool = MASK_POOLS[span.type] ?? MASK_POOLS.CUSTOM;
  return pool[index % pool.length];
}

function anonToken(span: DetectedSpan): string {
  const id = sha256(span.text.toLowerCase()).slice(0, 8).toUpperCase();
  if (span.type === "EMAIL") return `${id}@anon.example`;
  return id;
}

export function detectSpans(text: string, options: ProtectOptions): DetectedSpan[] {
  const types = new Set(options.entityTypes);
  const spans: DetectedSpan[] = [];

  if (options.method === "domain") {
    const domain = options.domain ?? "general";
    for (const { type, pattern } of DOMAIN_PATTERNS[domain]) {
      pushRegexSpans(text, pattern, type, spans);
    }
    if (options.useNer !== false) {
      spans.push(...compromiseSpans(text, new Set(["PERSON", "ORG", "GPE"])));
    }
  } else {
    if (types.has("EMAIL")) pushRegexSpans(text, EMAIL_RE, "EMAIL", spans);
    if (types.has("PERSON")) {
      pushRegexSpans(text, /\b[A-Z][a-z]{2,}\s[A-Z][a-z]{2,}\b/g, "PERSON", spans);
    }
    if (types.has("SSN")) pushRegexSpans(text, SSN_RE, "SSN", spans);
    if (types.has("PHONE")) pushRegexSpans(text, PHONE_RE, "PHONE", spans);
    if (types.has("CREDIT_CARD")) pushRegexSpans(text, CARD_RE, "CREDIT_CARD", spans);
    if (types.has("BANK_ACCOUNT")) pushRegexSpans(text, /\b\d{12,16}\b/g, "BANK_ACCOUNT", spans);
    if (types.has("MONEY")) pushRegexSpans(text, MONEY_RE, "MONEY", spans);
    if (options.useNer !== false) {
      spans.push(...compromiseSpans(text, types));
    }
  }

  if (options.customWords?.length) {
    for (const word of options.customWords) {
      const trimmed = word.trim();
      if (!trimmed) continue;
      const re = new RegExp(trimmed.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
      pushRegexSpans(text, re, "CUSTOM", spans);
    }
  }

  return mergeSpans(spans);
}

export function applySpans(
  text: string,
  spans: DetectedSpan[],
  options: ProtectOptions,
): string {
  const level = options.redactionLevel ?? "high";
  let result = text;
  const reversed = [...spans].sort((a, b) => b.start - a.start);
  reversed.forEach((span, index) => {
    let replacement: string;
    if (options.method === "masking") {
      replacement = maskToken(span, index);
    } else if (options.method === "anonymization") {
      replacement = anonToken(span);
    } else {
      replacement = redactToken(span.text, level);
    }
    result = result.slice(0, span.start) + replacement + result.slice(span.end);
  });
  return result;
}

export function countEntities(spans: DetectedSpan[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const span of spans) {
    counts[span.type] = (counts[span.type] ?? 0) + 1;
  }
  return counts;
}

export function protectText(text: string, options: ProtectOptions): ProtectResult {
  const spans = detectSpans(text, options);
  const processed = applySpans(text, spans, options);
  return {
    original: text,
    processed,
    spans,
    counts: countEntities(spans),
  };
}

export function analyzeText(text: string): Record<string, number> {
  const spans = detectSpans(text, {
    method: "redaction",
    entityTypes: [
      "PERSON",
      "ORG",
      "GPE",
      "LOC",
      "DATE",
      "EMAIL",
      "PHONE",
      "SSN",
      "CREDIT_CARD",
      "MONEY",
    ],
  });
  return countEntities(spans);
}
