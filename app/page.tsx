import Image from "next/image";
import Link from "next/link";
import { SiteFooter } from "@/components/site-footer";
import { SiteNav } from "@/components/site-nav";
import { Reveal } from "@/components/reveal";
import { getCurrentUser } from "@/lib/session";

const steps = [
  {
    title: "Load a document",
    body: "Paste text or upload PDF, DOCX, PPTX, CSV, or plain files. Images can be scanned for the same fields.",
  },
  {
    title: "Choose what to catch",
    body: "Pick people, places, emails, cards, and custom words. Domain packs cover finance, health, and personal files.",
  },
  {
    title: "Transform in one pass",
    body: "Redact, mask with stand-in values, or anonymize to stable IDs. Optionally lock the original with AES-256-GCM.",
  },
  {
    title: "Keep a chain, not a local node",
    body: "Each run writes a hash-linked audit record. No Ganache process, no private chain, and it still works on a hosted server.",
  },
];

export default async function HomePage() {
  const user = await getCurrentUser();
  return (
    <>
      <SiteNav user={user} />
      <main id="content">
        <section className="mx-auto grid min-h-[100dvh] max-w-[1400px] items-center gap-10 px-4 pb-16 pt-20 md:grid-cols-[minmax(0,1.05fr)_minmax(0,0.95fr)] md:gap-16 md:px-8 md:pt-16">
          <div>
            <p className="mb-4 font-mono text-[11px] uppercase tracking-[0.18em] text-muted">
              Data protection
            </p>
            <h1 className="max-w-[14ch] text-4xl font-semibold tracking-tighter text-ink md:text-6xl md:leading-[1.05]">
              Black out what should never travel.
            </h1>
            <p className="mt-5 max-w-[36ch] text-base leading-relaxed text-muted md:text-lg">
              Find personal data in documents, replace it on your terms, and keep a tamper-evident record of every pass.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-3">
              <Link
                href={user ? "/protect" : "/login"}
                className="inline-flex h-11 items-center rounded-[8px] bg-accent px-4 text-sm text-[#f3f4f2] transition-transform duration-200 hover:bg-accent-strong active:scale-[0.98]"
              >
                Open workspace
              </Link>
              <Link
                href="#method"
                className="inline-flex h-11 items-center rounded-[8px] border border-line px-4 text-sm text-ink transition-colors hover:bg-bg-elevated"
              >
                See the method
              </Link>
            </div>
          </div>
          <div className="relative">
            <Image
              src="/images/hero-redacted-desk.png"
              alt="Printed documents on a desk with solid black redaction bars covering sensitive lines"
              width={1536}
              height={1024}
              priority
              className="h-auto w-full rounded-[12px] object-cover shadow-[var(--shadow)]"
            />
          </div>
        </section>

        <section id="method" className="border-t border-line">
          <div className="mx-auto max-w-[1400px] px-4 py-20 md:px-8 md:py-28">
            <Reveal>
              <h2 className="max-w-[16ch] text-3xl font-semibold tracking-tight md:text-5xl">
                Four moves, one workspace.
              </h2>
            </Reveal>
            <ol className="mt-12 grid gap-x-12 gap-y-10 md:grid-cols-2">
              {steps.map((step, index) => (
                <Reveal key={step.title} delay={index * 0.05}>
                  <li className="grid grid-cols-[auto_1fr] gap-4">
                    <span className="font-mono text-sm tabular-nums text-accent">{String(index + 1).padStart(2, "0")}</span>
                    <div>
                      <h3 className="text-xl font-medium tracking-tight">{step.title}</h3>
                      <p className="mt-2 max-w-[58ch] text-base leading-relaxed text-muted">{step.body}</p>
                    </div>
                  </li>
                </Reveal>
              ))}
            </ol>
          </div>
        </section>

        <section className="border-t border-line bg-bg-elevated">
          <div className="mx-auto max-w-[1400px] px-4 py-20 md:px-8 md:py-28">
            <Reveal>
              <h2 className="text-3xl font-semibold tracking-tight md:text-5xl">Pick the transform.</h2>
            </Reveal>
            <div className="mt-12 grid gap-4 md:grid-cols-8">
              <article className="relative overflow-hidden rounded-[12px] bg-bg md:col-span-4 md:row-span-2">
                <Image
                  src="/images/feature-redacted-form.png"
                  alt="Overhead photograph of a paper form with black rectangles covering personal fields"
                  width={1536}
                  height={1024}
                  className="h-full min-h-[280px] w-full object-cover md:min-h-[460px]"
                />
                <div className="absolute inset-x-0 bottom-0 bg-[linear-gradient(transparent,rgb(16_20_18/0.82))] p-6 text-[#e7ece9]">
                  <h3 className="text-2xl font-medium">Redaction</h3>
                  <p className="mt-1 max-w-[48ch] text-sm leading-relaxed text-[#c7d0cb]">
                    Replace hits with a marker. High, medium, and low levels keep more or less of the original shape.
                  </p>
                </div>
              </article>
              <article className="rounded-[12px] bg-bg p-6 md:col-span-4">
                <h3 className="text-xl font-medium">Masking</h3>
                <p className="mt-2 max-w-[54ch] text-sm leading-relaxed text-muted">
                  Swap real values for lookalike stand-ins so layouts still read as documents, not holes.
                </p>
              </article>
              <article className="rounded-[12px] bg-accent-soft p-6 md:col-span-2">
                <h3 className="text-xl font-medium">Anonymization</h3>
                <p className="mt-2 text-sm leading-relaxed text-muted">
                  Map each value to a stable eight-character ID so repeats stay consistent inside a file.
                </p>
              </article>
              <article className="relative overflow-hidden rounded-[12px] md:col-span-2">
                <Image
                  src="/images/feature-workspace.png"
                  alt="Laptop on a dark desk showing a document with blacked-out text blocks"
                  width={1536}
                  height={1024}
                  className="h-full min-h-[160px] w-full object-cover"
                />
                <div className="absolute inset-x-0 bottom-0 bg-[linear-gradient(transparent,rgb(16_20_18/0.78))] p-4 text-[#e7ece9]">
                  <h3 className="text-lg font-medium">Domain packs</h3>
                  <p className="mt-1 text-sm text-[#c7d0cb]">Finance, health, personal, general.</p>
                </div>
              </article>
            </div>
          </div>
        </section>

        <section className="border-t border-line">
          <div className="mx-auto grid max-w-[1400px] gap-10 px-4 py-20 md:grid-cols-[1.1fr_0.9fr] md:items-center md:px-8 md:py-28">
            <Reveal>
              <div>
                <h2 className="max-w-[16ch] text-3xl font-semibold tracking-tight md:text-5xl">
                  Audit without a local blockchain.
                </h2>
                <p className="mt-5 max-w-[62ch] text-base leading-relaxed text-muted">
                  The first build wrote logs to Ganache on 127.0.0.1:7545. That cannot run on Streamlit Community Cloud or any hosted web service. RE-DACT now stores a hash chain: each log includes the previous hash, so tampering breaks verification. Optional public RPC support can wait until you actually need a public network.
                </p>
              </div>
            </Reveal>
            <Reveal delay={0.08}>
              <div className="rounded-[12px] border border-line bg-bg-elevated p-6 font-mono text-[12px] leading-7 text-muted">
                <p>previous  0000...0000</p>
                <p>action    redaction</p>
                <p>hash      7f3c9ae21b</p>
                <p>chain     sha256(prev|user|action|hash|time)</p>
                <p className="text-accent">status    verified</p>
              </div>
            </Reveal>
          </div>
        </section>

        <section className="border-t border-line">
          <div className="mx-auto max-w-[1400px] px-4 py-20 md:px-8 md:py-24">
            <div className="grid items-end gap-8 md:grid-cols-[1.4fr_auto]">
              <div>
                <h2 className="max-w-[18ch] text-3xl font-semibold tracking-tight md:text-5xl">
                  Run a pass on your own files.
                </h2>
                <p className="mt-4 max-w-[54ch] text-base text-muted">
                  Demo login: demo@redact.app / redact-demo-2026. Create a private account when you are ready to keep a separate ledger.
                </p>
              </div>
            </div>
          </div>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
