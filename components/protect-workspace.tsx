"use client";

import { useState } from "react";
import { ENTITY_TYPES, type EntityType, type ProtectionMethod, type RedactionLevel, type Domain } from "@/lib/types";

const METHODS: { id: ProtectionMethod; label: string; hint: string }[] = [
  { id: "redaction", label: "Redaction", hint: "Replace hits with a marker" },
  { id: "masking", label: "Masking", hint: "Swap in lookalike values" },
  { id: "anonymization", label: "Anonymization", hint: "Stable IDs per value" },
  { id: "domain", label: "Domain pack", hint: "Finance, health, personal, general" },
];

const SAMPLE = `From: Priya Shah <priya.shah@northwind.test>
Phone: +1 312 555 0142
SSN: 123-45-6789
Card: 4111 1111 1111 1111
Notes: Northwind Labs billed $12,400.00 on 04/18/2024 for Project Kestrel.`;

type ProtectResponse = {
  processed: string;
  counts: Record<string, number>;
  dataHash: string;
  filename: string;
  encryption?: { key: string; ciphertext: string } | null;
  error?: string;
};

export function ProtectWorkspace() {
  const [text, setText] = useState(SAMPLE);
  const [method, setMethod] = useState<ProtectionMethod>("redaction");
  const [level, setLevel] = useState<RedactionLevel>("high");
  const [domain, setDomain] = useState<Domain>("general");
  const [entities, setEntities] = useState<EntityType[]>(["PERSON", "ORG", "GPE", "DATE", "EMAIL", "PHONE", "SSN", "CREDIT_CARD"]);
  const [customWords, setCustomWords] = useState("Kestrel");
  const [useEncryption, setUseEncryption] = useState(false);
  const [pending, setPending] = useState(false);
  const [extracting, setExtracting] = useState(false);
  const [imagePending, setImagePending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ProtectResponse | null>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);

  function toggleEntity(type: EntityType) {
    setEntities((current) =>
      current.includes(type) ? current.filter((item) => item !== type) : [...current, type],
    );
  }

  async function onFile(file: File) {
    setExtracting(true);
    setError(null);
    try {
      const form = new FormData();
      form.append("file", file);
      const response = await fetch("/api/extract", { method: "POST", body: form });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Could not read file");
      setText(data.text);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not read file");
    } finally {
      setExtracting(false);
    }
  }

  async function onImage(file: File) {
    setImagePending(true);
    setError(null);
    try {
      const form = new FormData();
      form.append("file", file);
      const response = await fetch("/api/image-redact", { method: "POST", body: form });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Image redaction failed");
      setImagePreview(data.image);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Image redaction failed");
    } finally {
      setImagePending(false);
    }
  }

  async function processText() {
    setPending(true);
    setError(null);
    try {
      const response = await fetch("/api/protect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text,
          method,
          entityTypes: entities,
          customWords: customWords.split(",").map((w) => w.trim()).filter(Boolean),
          redactionLevel: method === "redaction" ? level : undefined,
          domain: method === "domain" ? domain : undefined,
          useEncryption,
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Protection failed");
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Protection failed");
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="grid gap-8 lg:grid-cols-[320px_minmax(0,1fr)]">
      <aside className="flex flex-col gap-6">
        <div>
          <h1 className="text-3xl font-semibold tracking-tight">Protect</h1>
          <p className="mt-2 text-sm leading-relaxed text-muted">
            Load text or a document, pick a transform, then run a pass. Results are hashed into the audit chain.
          </p>
        </div>
        <fieldset className="flex flex-col gap-2">
          <legend className="text-sm">Method</legend>
          {METHODS.map((item) => (
            <label key={item.id} className="flex cursor-pointer gap-3 rounded-[8px] border border-line px-3 py-2 has-[:checked]:border-accent">
              <input
                type="radio"
                name="method"
                className="mt-1"
                checked={method === item.id}
                onChange={() => setMethod(item.id)}
              />
              <span>
                <span className="block text-sm">{item.label}</span>
                <span className="block text-xs text-muted">{item.hint}</span>
              </span>
            </label>
          ))}
        </fieldset>
        {method === "redaction" ? (
          <label className="flex flex-col gap-2 text-sm">
            Redaction level
            <select
              value={level}
              onChange={(e) => setLevel(e.target.value as RedactionLevel)}
              className="h-11 rounded-[8px] border border-line bg-bg px-3"
            >
              <option value="high">High (full marker)</option>
              <option value="medium">Medium (length kept)</option>
              <option value="low">Low (two-letter prefix)</option>
            </select>
          </label>
        ) : null}
        {method === "domain" ? (
          <label className="flex flex-col gap-2 text-sm">
            Domain
            <select
              value={domain}
              onChange={(e) => setDomain(e.target.value as Domain)}
              className="h-11 rounded-[8px] border border-line bg-bg px-3"
            >
              <option value="general">General</option>
              <option value="financial">Financial</option>
              <option value="personal">Personal</option>
              <option value="health">Health</option>
            </select>
          </label>
        ) : null}
        <fieldset>
          <legend className="mb-2 text-sm">Entities</legend>
          <div className="flex flex-wrap gap-2">
            {ENTITY_TYPES.filter((type) => type !== "CUSTOM").map((type) => (
              <label
                key={type}
                className={`cursor-pointer rounded-[8px] border px-2 py-1 text-xs ${entities.includes(type) ? "border-accent bg-accent-soft" : "border-line"}`}
              >
                <input
                  type="checkbox"
                  className="sr-only"
                  checked={entities.includes(type)}
                  onChange={() => toggleEntity(type)}
                />
                {type}
              </label>
            ))}
          </div>
        </fieldset>
        <label className="flex flex-col gap-2 text-sm">
          Custom words
          <input
            value={customWords}
            onChange={(e) => setCustomWords(e.target.value)}
            className="h-11 rounded-[8px] border border-line bg-bg px-3"
            placeholder="Comma-separated"
          />
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={useEncryption} onChange={(e) => setUseEncryption(e.target.checked)} />
          Encrypt the original (AES-256-GCM)
        </label>
        <button
          type="button"
          onClick={processText}
          disabled={pending || !text.trim()}
          className="h-11 rounded-[8px] bg-accent text-sm text-[#f3f4f2] hover:bg-accent-strong disabled:opacity-60"
        >
          {pending ? "Running pass..." : "Run pass"}
        </button>
      </aside>

      <section className="flex flex-col gap-6">
        <div className="flex flex-wrap gap-3">
          <label className="inline-flex h-10 cursor-pointer items-center rounded-[8px] border border-line px-3 text-sm">
            Upload document
            <input
              type="file"
              className="sr-only"
              accept=".txt,.csv,.md,.pdf,.docx,.pptx"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) void onFile(file);
              }}
            />
          </label>
          <label className="inline-flex h-10 cursor-pointer items-center rounded-[8px] border border-line px-3 text-sm">
            Redact image
            <input
              type="file"
              className="sr-only"
              accept="image/png,image/jpeg,image/webp"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) void onImage(file);
              }}
            />
          </label>
          {(extracting || imagePending) && <p className="self-center text-sm text-muted">Working on the file...</p>}
        </div>
        {error ? <p className="text-sm text-danger">{error}</p> : null}
        <label className="flex flex-col gap-2 text-sm">
          Source
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            className="min-h-[240px] rounded-[12px] border border-line bg-bg p-4 font-mono text-sm leading-6 outline-none ring-accent focus:ring-2"
          />
        </label>
        {result ? (
          <div className="rounded-[12px] border border-line bg-bg-elevated p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h2 className="text-lg font-medium">Result</h2>
              <a
                href={`data:text/plain;charset=utf-8,${encodeURIComponent(result.processed)}`}
                download={result.filename}
                className="text-sm text-accent hover:text-accent-strong"
              >
                Download
              </a>
            </div>
            <pre className="mt-3 whitespace-pre-wrap font-mono text-sm leading-6">{result.processed}</pre>
            <p className="mt-3 font-mono text-xs text-muted">hash {result.dataHash}</p>
            {result.counts && Object.keys(result.counts).length > 0 ? (
              <p className="mt-2 text-xs text-muted">
                {Object.entries(result.counts)
                  .map(([key, value]) => `${key} ${value}`)
                  .join("  ")}
              </p>
            ) : (
              <p className="mt-2 text-xs text-muted">No entities matched. Try more types or custom words.</p>
            )}
            {result.encryption ? (
              <div className="mt-4 grid gap-3">
                <label className="flex flex-col gap-1 text-xs text-muted">
                  Encryption key (save this; it is not stored)
                  <textarea readOnly value={result.encryption.key} className="min-h-[72px] rounded-[8px] border border-line bg-bg p-2 font-mono text-xs" />
                </label>
                <label className="flex flex-col gap-1 text-xs text-muted">
                  Encrypted original
                  <textarea readOnly value={result.encryption.ciphertext} className="min-h-[96px] rounded-[8px] border border-line bg-bg p-2 font-mono text-xs" />
                </label>
              </div>
            ) : null}
          </div>
        ) : (
          <div className="rounded-[12px] border border-dashed border-line p-6 text-sm text-muted">
            Run a pass to see protected text here. Empty results still write an audit record if you submit.
          </div>
        )}
        {imagePreview ? (
          <div>
            <h2 className="text-lg font-medium">Redacted image</h2>
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img src={imagePreview} alt="Image after OCR-based redaction boxes were applied" className="mt-3 max-w-full rounded-[12px]" />
          </div>
        ) : null}
      </section>
    </div>
  );
}
