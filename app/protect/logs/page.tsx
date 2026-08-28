import { getCurrentUser } from "@/lib/session";
import { listAuditLogs } from "@/lib/db";
import { verifyAuditChain } from "@/lib/audit";
import { redirect } from "next/navigation";

export const metadata = { title: "Logs" };

export default async function LogsPage() {
  const user = await getCurrentUser();
  if (!user) redirect("/login?next=/protect/logs");
  const logs = listAuditLogs(user.id);
  const status = verifyAuditChain();

  return (
    <div>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-semibold tracking-tight">Audit logs</h1>
          <p className="mt-2 max-w-[54ch] text-sm text-muted">
            Each pass is linked to the previous hash. This is the hosted replacement for Ganache.
          </p>
        </div>
        <a href="/protect/logs" className="h-10 rounded-[8px] border border-line px-3 text-sm leading-10 hover:bg-bg-elevated">
          Refresh
        </a>
      </div>
      <p className={`mt-6 text-sm ${status.valid ? "text-accent" : "text-danger"}`}>
        {status.valid
          ? `Chain verified across ${status.checked} records.`
          : `Chain broken after checking ${status.checked} records.`}
      </p>
      {logs.length === 0 ? (
        <p className="mt-8 text-sm text-muted">No logs yet. Run a protection pass to write the first link.</p>
      ) : (
        <ul className="mt-8 grid gap-3">
          {logs.map((log) => (
            <li key={log.id} className="rounded-[12px] border border-line bg-bg-elevated p-4">
              <p className="text-sm font-medium">{log.action}</p>
              <p className="mt-1 text-xs text-muted">{new Date(log.created_at).toLocaleString()}</p>
              <p className="mt-3 break-all font-mono text-[11px] text-muted">data {log.data_hash}</p>
              <p className="break-all font-mono text-[11px] text-muted">chain {log.chain_hash}</p>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
