import { AppShell } from "@/components/app-shell";
import { getCurrentUser } from "@/lib/session";
import { redirect } from "next/navigation";

export default async function ProtectLayout({ children }: { children: React.ReactNode }) {
  const user = await getCurrentUser();
  if (!user) redirect("/login?next=/protect");
  return <AppShell user={user}>{children}</AppShell>;
}
