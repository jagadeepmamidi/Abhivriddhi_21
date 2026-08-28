import { NextResponse } from "next/server";
import { errorResponse, requireUser } from "@/lib/api";
import { extractTextFromFile } from "@/lib/extract";

export async function POST(request: Request) {
  const auth = await requireUser();
  if (!auth.user) return auth.response;
  try {
    const form = await request.formData();
    const file = form.get("file");
    if (!(file instanceof File)) {
      return NextResponse.json({ error: "Choose a file to extract" }, { status: 400 });
    }
    const buffer = Buffer.from(await file.arrayBuffer());
    const text = await extractTextFromFile(file.name, buffer);
    return NextResponse.json({ text, filename: file.name });
  } catch (error) {
    return errorResponse(error);
  }
}
