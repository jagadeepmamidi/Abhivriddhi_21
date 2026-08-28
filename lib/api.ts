import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/session";

export async function requireUser() {
  const user = await getCurrentUser();
  if (!user) {
    return { user: null, response: NextResponse.json({ error: "Sign in required" }, { status: 401 }) };
  }
  return { user, response: null };
}

export function errorResponse(error: unknown, fallback = "Request failed") {
  const message = error instanceof Error ? error.message : fallback;
  const status = message === "Sign in required" ? 401 : 400;
  return NextResponse.json({ error: message }, { status });
}
