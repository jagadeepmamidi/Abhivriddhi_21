"use client";

import { useState } from "react";

export default function DecryptPage() {
  const [ciphertext, setCiphertext] = useState("");
  const [key, setKey] = useState("");
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function decrypt() {
    setPending(true);
    setError(null);
    setText(null);
    try {
      const response = await fetch("/api/decrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ciphertext, key }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Decryption failed");
      setText(data.text);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Decryption failed");
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="max-w-3xl">
      <h1 className="text-3xl font-semibold tracking-tight">Decrypt</h1>
      <p className="mt-2 text-sm text-muted">
        Paste the ciphertext and the one-time key from a protection pass that used encryption. Keys are not stored on the server.
      </p>
      <label className="mt-8 flex flex-col gap-2 text-sm">
        Ciphertext
        <textarea
          value={ciphertext}
          onChange={(e) => setCiphertext(e.target.value)}
          className="min-h-[140px] rounded-[12px] border border-line bg-bg p-3 font-mono text-sm"
        />
      </label>
      <label className="mt-4 flex flex-col gap-2 text-sm">
        Key
        <textarea
          value={key}
          onChange={(e) => setKey(e.target.value)}
          className="min-h-[72px] rounded-[12px] border border-line bg-bg p-3 font-mono text-sm"
        />
      </label>
      {error ? <p className="mt-3 text-sm text-danger">{error}</p> : null}
      <button
        type="button"
        onClick={decrypt}
        disabled={pending || !ciphertext || !key}
        className="mt-4 h-11 rounded-[8px] bg-accent px-4 text-sm text-[#f3f4f2] hover:bg-accent-strong disabled:opacity-60"
      >
        {pending ? "Decrypting..." : "Decrypt"}
      </button>
      {text ? (
        <pre className="mt-6 whitespace-pre-wrap rounded-[12px] border border-line bg-bg-elevated p-4 font-mono text-sm">{text}</pre>
      ) : null}
    </div>
  );
}
