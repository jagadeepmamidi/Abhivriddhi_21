import { SiteFooter } from "@/components/site-footer";
import { SiteNav } from "@/components/site-nav";
import { getCurrentUser } from "@/lib/session";

export const metadata = { title: "Terms" };

export default async function TermsPage() {
  const user = await getCurrentUser();
  return (
    <>
      <SiteNav user={user} />
      <main id="content" className="mx-auto max-w-[800px] px-4 py-16 md:px-8 md:py-24">
        <h1 className="text-4xl font-semibold tracking-tighter">Terms</h1>
        <p className="mt-6 text-base leading-relaxed text-muted">
          RE-DACT is provided as-is for document protection experiments and internal workflows. Detection is heuristic. It will miss some entities and can over-redact others. You are responsible for reviewing output before sharing it.
        </p>
        <p className="mt-4 text-base leading-relaxed text-muted">
          The hash chain records that a pass happened. It is not a legal compliance certification.
        </p>
      </main>
      <SiteFooter />
    </>
  );
}
