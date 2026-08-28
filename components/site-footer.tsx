import Link from "next/link";

export function SiteFooter() {
  return (
    <footer className="border-t border-line">
      <div className="mx-auto flex max-w-[1400px] flex-col gap-4 px-4 py-10 md:flex-row md:items-center md:justify-between md:px-8">
        <p className="font-mono text-sm text-muted">RE-DACT</p>
        <nav className="flex flex-wrap gap-5 text-sm text-muted" aria-label="Footer">
          <Link href="/about" className="hover:text-ink">
            About
          </Link>
          <Link href="/privacy" className="hover:text-ink">
            Privacy
          </Link>
          <Link href="/terms" className="hover:text-ink">
            Terms
          </Link>
          <Link href="/login" className="hover:text-ink">
            Log in
          </Link>
        </nav>
      </div>
    </footer>
  );
}
