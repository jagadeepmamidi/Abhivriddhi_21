import { NextResponse } from "next/server";
import { errorResponse, requireUser } from "@/lib/api";
import { getDownload } from "@/lib/db";

export async function GET(
  _request: Request,
  context: { params: Promise<{ id: string }> },
) {
  const auth = await requireUser();
  if (!auth.user) return auth.response;
  try {
    const { id } = await context.params;
    const row = getDownload(id, auth.user.id);
    if (!row) return NextResponse.json({ error: "File not found" }, { status: 404 });
    return new NextResponse(new Uint8Array(row.content), {
      headers: {
        "Content-Type": row.mime,
        "Content-Disposition": `attachment; filename="${row.filename}"`,
      },
    });
  } catch (error) {
    return errorResponse(error);
  }
}
