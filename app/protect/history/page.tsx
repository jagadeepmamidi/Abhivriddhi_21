import { getCurrentUser } from "@/lib/session";
import { listDownloads } from "@/lib/db";
import { redirect } from "next/navigation";

export const metadata = { title: "History" };

export default async function HistoryPage() {
  const user = await getCurrentUser();
  if (!user) redirect("/login?next=/protect/history");
  const items = listDownloads(user.id);

  return (
    <div>
      <h1 className="text-3xl font-semibold tracking-tight">History</h1>
      <p className="mt-2 max-w-[54ch] text-sm text-muted">
        Protected outputs and redacted images are stored in the database so they survive process restarts on a persistent disk.
      </p>
      {items.length === 0 ? (
        <p className="mt-8 text-sm text-muted">Nothing saved yet. Run a pass on the Protect screen.</p>
      ) : (
        <ul className="mt-8 grid gap-2">
          {items.map((item) => (
            <li key={item.id} className="flex flex-wrap items-center justify-between gap-3 border-b border-line py-3">
              <div>
                <p className="text-sm">{item.filename}</p>
                <p className="text-xs text-muted">{new Date(item.created_at).toLocaleString()}</p>
              </div>
              <a href={`/api/history/${item.id}`} className="text-sm text-accent hover:text-accent-strong">
                Download
              </a>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
