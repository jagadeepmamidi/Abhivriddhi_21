import { Suspense } from "react";
import { AuthPanel } from "@/components/auth-panel";
import { SiteFooter } from "@/components/site-footer";
import { SiteNav } from "@/components/site-nav";
import { getCurrentUser } from "@/lib/session";

export const metadata = { title: "Create account" };

export default async function SignupPage() {
  const user = await getCurrentUser();
  return (
    <>
      <SiteNav user={user} />
      <main id="content" className="mx-auto flex w-full max-w-[1400px] flex-1 px-4 py-16 md:px-8">
        <div className="grid w-full items-start gap-12 md:grid-cols-[1fr_420px]">
          <div>
            <h1 className="max-w-[12ch] text-4xl font-semibold tracking-tighter md:text-6xl">
              Start a private ledger.
            </h1>
            <p className="mt-4 max-w-[46ch] text-base leading-relaxed text-muted">
              Accounts are local to this deployment. We do not use the old Firebase keys from the Streamlit build.
            </p>
          </div>
          <div className="rounded-[12px] border border-line bg-bg-elevated p-6">
            <Suspense fallback={<div className="h-64 animate-pulse rounded-[8px] bg-bg" />}>
              <AuthPanel mode="signup" />
            </Suspense>
          </div>
        </div>
      </main>
      <SiteFooter />
    </>
  );
}
