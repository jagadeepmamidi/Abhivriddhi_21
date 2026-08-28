import Link from "next/link";
import { SiteFooter } from "@/components/site-footer";
import { SiteNav } from "@/components/site-nav";
import { getCurrentUser } from "@/lib/session";

export default async function NotFound() {
  const user = await getCurrentUser();
  return (
    <>
      <SiteNav user={user} />
      <main id="content" className="mx-auto flex min-h-[70dvh] max-w-[800px] flex-col justify-center px-4 py-16">
        <p className="font-mono text-sm text-muted">404</p>
        <h1 className="mt-3 text-4xl font-semibold tracking-tighter">This page is not in the file.</h1>
        <Link href="/" className="mt-8 w-fit text-sm text-accent hover:text-accent-strong">
          Back to home
        </Link>
      </main>
      <SiteFooter />
    </>
  );
}
