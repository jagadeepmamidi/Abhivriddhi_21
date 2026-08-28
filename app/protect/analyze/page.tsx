"use client";

import { useState } from "react";

export default function AnalyzePage() {
  const [text, setText] = useState("Priya Shah (priya.shah@northwind.test) met Northwind Labs in Cedar Falls on 04/18/2024.");
  const [counts, setCounts] = useState<Record<string, number> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function analyze() {
    setPending(true);
    setError(null);
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Analysis failed");
      setCounts(data.counts);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Analysis failed");
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="grid gap-8 lg:grid-cols-[1fr_320px]">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight">Analyze</h1>
        <p className="mt-2 max-w-[54ch] text-sm text-muted">
          Count detected entities without rewriting the source. Use this to see what a protection pass would hit.
        </p>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          className="mt-6 min-h-[280px] w-full rounded-[12px] border border-line bg-bg p-4 font-mono text-sm"
        />
        {error ? <p className="mt-3 text-sm text-danger">{error}</p> : null}
        <button
          type="button"
          onClick={analyze}
          disabled={pending}
          className="mt-4 h-11 rounded-[8px] bg-accent px-4 text-sm text-[#f3f4f2] hover:bg-accent-strong disabled:opacity-60"
        >
          {pending ? "Counting..." : "Analyze"}
        </button>
      </div>
      <aside className="rounded-[12px] border border-line bg-bg-elevated p-5">
        <h2 className="text-lg font-medium">Counts</h2>
        {counts && Object.keys(counts).length ? (
          <ul className="mt-4 grid gap-2">
            {Object.entries(counts).map(([key, value]) => (
              <li key={key} className="flex justify-between font-mono text-sm">
                <span>{key}</span>
                <span className="tabular-nums">{value}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-4 text-sm text-muted">No counts yet. Analyze a document to fill this panel.</p>
        )}
      </aside>
    </div>
  );
}
