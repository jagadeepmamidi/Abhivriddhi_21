"use client";

import { Moon, Sun } from "@phosphor-icons/react";
import { useSyncExternalStore } from "react";

function subscribe(onStoreChange: () => void) {
  window.addEventListener("redact-theme", onStoreChange);
  window.addEventListener("storage", onStoreChange);
  return () => {
    window.removeEventListener("redact-theme", onStoreChange);
    window.removeEventListener("storage", onStoreChange);
  };
}

function getTheme(): "light" | "dark" {
  return document.documentElement.classList.contains("dark") ? "dark" : "light";
}

export function ThemeToggle() {
  const theme = useSyncExternalStore(subscribe, getTheme, () => "light");

  function toggle() {
    const next = theme === "dark" ? "light" : "dark";
    document.documentElement.classList.toggle("dark", next === "dark");
    localStorage.setItem("redact-theme", next);
    window.dispatchEvent(new Event("redact-theme"));
  }

  return (
    <button
      type="button"
      onClick={toggle}
      className="inline-flex h-9 w-9 items-center justify-center rounded-[8px] text-ink transition-transform duration-200 hover:bg-bg-elevated active:scale-[0.98]"
      aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
    >
      {theme === "dark" ? <Sun size={18} weight="regular" /> : <Moon size={18} weight="regular" />}
    </button>
  );
}
