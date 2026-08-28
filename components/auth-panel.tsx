"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

type Mode = "login" | "signup";

export function AuthPanel({ mode }: { mode: Mode }) {
  const router = useRouter();
  const params = useSearchParams();
  const next = params.get("next") || "/protect";
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState(mode === "login" ? "demo@redact.app" : "");
  const [password, setPassword] = useState(mode === "login" ? "redact-demo-2026" : "");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      const payload =
        mode === "signup" ? { username, email, password } : { email, password };
      const response = await fetch(`/api/auth/${mode}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok) {
        setError(data.error || "Could not continue");
        return;
      }
      router.push(next);
      router.refresh();
    } catch {
      setError("Network error. Try again.");
    } finally {
      setPending(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="flex flex-col gap-4">
      {mode === "signup" ? (
        <label className="flex flex-col gap-2 text-sm">
          Username
          <input
            required
            minLength={2}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="h-11 rounded-[8px] border border-line bg-bg px-3 text-ink outline-none ring-accent focus:ring-2"
            autoComplete="username"
          />
        </label>
      ) : null}
      <label className="flex flex-col gap-2 text-sm">
        Email
        <input
          required
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="h-11 rounded-[8px] border border-line bg-bg px-3 text-ink outline-none ring-accent focus:ring-2"
          autoComplete="email"
        />
      </label>
      <label className="flex flex-col gap-2 text-sm">
        Password
        <input
          required
          type="password"
          minLength={mode === "signup" ? 8 : 1}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="h-11 rounded-[8px] border border-line bg-bg px-3 text-ink outline-none ring-accent focus:ring-2"
          autoComplete={mode === "signup" ? "new-password" : "current-password"}
        />
        {mode === "signup" ? (
          <span className="text-xs text-muted">At least 8 characters.</span>
        ) : (
          <span className="text-xs text-muted">Demo is prefilled. Change it if you created your own account.</span>
        )}
      </label>
      {error ? <p className="text-sm text-danger">{error}</p> : null}
      <button
        type="submit"
        disabled={pending}
        className="h-11 rounded-[8px] bg-accent text-sm text-[#f3f4f2] transition-transform hover:bg-accent-strong disabled:opacity-60 active:scale-[0.98]"
      >
        {pending ? "Working..." : mode === "signup" ? "Create account" : "Log in"}
      </button>
      <p className="text-sm text-muted">
        {mode === "signup" ? (
          <>
            Already have an account?{" "}
            <Link href="/login" className="text-ink underline decoration-line underline-offset-4">
              Log in
            </Link>
          </>
        ) : (
          <>
            Need an account?{" "}
            <Link href="/signup" className="text-ink underline decoration-line underline-offset-4">
              Create account
            </Link>
          </>
        )}
      </p>
    </form>
  );
}
