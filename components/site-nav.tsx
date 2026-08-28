import Link from "next/link";
import { ThemeToggle } from "@/components/theme-toggle";
import type { PublicUser } from "@/lib/types";

const navLink =
  "text-sm text-muted transition-colors hover:text-ink";

export function SiteNav({ user }: { user: PublicUser | null }) {
  return (
    <header className="sticky top-0 z-40 border-b border-line/80 bg-bg/85 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-[1400px] items-center justify-between px-4 md:px-8">
        <Link href="/" className="font-mono text-[15px] tracking-tight text-ink">
          RE-DACT
        </Link>
        <nav className="flex items-center gap-5" aria-label="Primary">
          <Link href="/about" className={navLink}>
            About
          </Link>
          {user ? null : (
            <Link href="/login" className={navLink}>
              Log in
            </Link>
          )}
          <ThemeToggle />
          <Link
            href={user ? "/protect" : "/signup"}
            className="inline-flex h-9 items-center rounded-[8px] bg-accent px-3 text-sm text-[#f3f4f2] transition-transform duration-200 hover:bg-accent-strong active:scale-[0.98]"
          >
            {user ? "Workspace" : "Create account"}
          </Link>
        </nav>
      </div>
    </header>
  );
}
