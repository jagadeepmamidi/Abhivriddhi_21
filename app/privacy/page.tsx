import { SiteFooter } from "@/components/site-footer";
import { SiteNav } from "@/components/site-nav";
import { getCurrentUser } from "@/lib/session";

export const metadata = { title: "Privacy" };

export default async function PrivacyPage() {
  const user = await getCurrentUser();
  return (
    <>
      <SiteNav user={user} />
      <main id="content" className="mx-auto max-w-[800px] px-4 py-16 md:px-8 md:py-24">
        <h1 className="text-4xl font-semibold tracking-tighter">Privacy</h1>
        <p className="mt-6 text-base leading-relaxed text-muted">
          RE-DACT stores account records, processed outputs you choose to keep, and hash-chained audit metadata on the server that hosts the app. Original files are processed in memory. Encryption keys are shown once in the browser and are not stored by default.
        </p>
        <p className="mt-4 text-base leading-relaxed text-muted">
          Do not upload data you are not allowed to process. Self-host if your policy requires it. This software does not send documents to a third-party NLP API.
        </p>
      </main>
      <SiteFooter />
    </>
  );
}
