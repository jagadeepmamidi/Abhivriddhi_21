import { NextResponse } from "next/server";
import { errorResponse, requireUser } from "@/lib/api";
import { listDownloads } from "@/lib/db";

export async function GET() {
  const auth = await requireUser();
  if (!auth.user) return auth.response;
  try {
    const items = listDownloads(auth.user.id);
    return NextResponse.json({ items });
  } catch (error) {
    return errorResponse(error);
  }
}
