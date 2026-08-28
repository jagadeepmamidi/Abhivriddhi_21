import { SiteFooter } from "@/components/site-footer";
import { SiteNav } from "@/components/site-nav";
import { getCurrentUser } from "@/lib/session";

export const metadata = { title: "About" };

export default async function AboutPage() {
  const user = await getCurrentUser();
  return (
    <>
      <SiteNav user={user} />
      <main id="content" className="mx-auto max-w-[800px] px-4 py-16 md:px-8 md:py-24">
        <h1 className="text-4xl font-semibold tracking-tighter md:text-6xl">About RE-DACT</h1>
        <p className="mt-6 text-base leading-relaxed text-muted">
          RE-DACT started as a Streamlit prototype: redaction, masking, anonymization, file upload, image OCR, encryption, and audit logs. The plan was sound. The original stack was not deployable. spaCy and EasyOCR were heavy, Firebase keys were hardcoded, and audit writes targeted Ganache on localhost.
        </p>
        <p className="mt-4 text-base leading-relaxed text-muted">
          This rebuild keeps the product: protect text and files, inspect entities, decrypt a stored original, and review a per-user history. The blockchain piece is replaced with a hash-chained ledger in SQLite (or a disk-backed file on Render). That is the hosted alternative to Ganache. It does not require a wallet, gas, or a private Ethereum node.
        </p>
        <h2 className="mt-12 text-2xl font-medium tracking-tight">What works now</h2>
        <ul className="mt-4 space-y-3 text-base leading-relaxed text-muted">
          <li>Text and file protection (PDF, DOCX, PPTX, TXT, CSV)</li>
          <li>Image redaction via on-server OCR</li>
          <li>Entity analysis</li>
          <li>AES-256-GCM encryption of the original</li>
          <li>Download history stored in the database, not a local JSON file</li>
          <li>Account sessions with httpOnly cookies</li>
        </ul>
      </main>
      <SiteFooter />
    </>
  );
}
