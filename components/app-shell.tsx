"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { SignOut, User } from "@phosphor-icons/react";
import { ThemeToggle } from "@/components/theme-toggle";
import type { PublicUser } from "@/lib/types";

const links = [
  { href: "/protect", label: "Protect" },
  { href: "/protect/analyze", label: "Analyze" },
  { href: "/protect/decrypt", label: "Decrypt" },
  { href: "/protect/logs", label: "Logs" },
  { href: "/protect/history", label: "History" },
];

export function AppShell({
  user,
  children,
}: {
  user: PublicUser;
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const router = useRouter();

  async function logout() {
    await fetch("/api/auth/logout", { method: "POST" });
    router.push("/");
    router.refresh();
  }

  return (
    <div className="flex min-h-[100dvh] flex-col">
      <header className="sticky top-0 z-40 border-b border-line bg-bg/90 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-[1400px] items-center justify-between gap-4 px-4 md:px-8">
          <Link href="/" className="font-mono text-[15px] tracking-tight">
            RE-DACT
          </Link>
          <nav className="hidden items-center gap-5 md:flex" aria-label="Workspace">
            {links.map((link) => {
              const active = pathname === link.href;
              return (
                <Link
                  key={link.href}
                  href={link.href}
                  className={`text-sm ${active ? "text-ink" : "text-muted hover:text-ink"}`}
                >
                  {link.label}
                </Link>
              );
            })}
          </nav>
          <div className="flex items-center gap-2">
            <span className="hidden items-center gap-1 text-sm text-muted sm:inline-flex">
              <User size={16} />
              {user.username}
            </span>
            <ThemeToggle />
            <button
              type="button"
              onClick={logout}
              className="inline-flex h-9 items-center gap-1 rounded-[8px] px-2 text-sm text-muted hover:text-ink"
            >
              <SignOut size={16} />
              Sign out
            </button>
          </div>
        </div>
        <nav className="flex gap-4 overflow-x-auto border-t border-line px-4 py-2 md:hidden" aria-label="Workspace mobile">
          {links.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className={`whitespace-nowrap text-sm ${pathname === link.href ? "text-ink" : "text-muted"}`}
            >
              {link.label}
            </Link>
          ))}
        </nav>
      </header>
      <main id="content" className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-8 md:px-8">
        {children}
      </main>
    </div>
  );
}
