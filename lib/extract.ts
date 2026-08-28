import JSZip from "jszip";
import mammoth from "mammoth";
import { extractText, getDocumentProxy } from "unpdf";

const MAX_BYTES = 12 * 1024 * 1024;

export const TEXT_EXTENSIONS = new Set([".txt", ".csv", ".md"]);
export const DOC_EXTENSIONS = new Set([".pdf", ".docx", ".pptx", ".txt", ".csv", ".md"]);
export const IMAGE_EXTENSIONS = new Set([".png", ".jpg", ".jpeg", ".webp"]);

export function extensionOf(filename: string): string {
  const idx = filename.lastIndexOf(".");
  return idx >= 0 ? filename.slice(idx).toLowerCase() : "";
}

async function extractPdf(buffer: Buffer): Promise<string> {
  const pdf = await getDocumentProxy(new Uint8Array(buffer));
  const { text } = await extractText(pdf, { mergePages: true });
  return Array.isArray(text) ? text.join("\n") : text;
}

async function extractDocx(buffer: Buffer): Promise<string> {
  const result = await mammoth.extractRawText({ buffer });
  return result.value;
}

async function extractPptx(buffer: Buffer): Promise<string> {
  const zip = await JSZip.loadAsync(buffer);
  const slideNames = Object.keys(zip.files)
    .filter((name) => /^ppt\/slides\/slide\d+\.xml$/i.test(name))
    .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  const chunks: string[] = [];
  for (const name of slideNames) {
    const xml = await zip.files[name].async("string");
    const texts = [...xml.matchAll(/<a:t[^>]*>([^<]*)<\/a:t>/g)].map((m) => m[1]);
    if (texts.length) chunks.push(texts.join(" "));
  }
  return chunks.join("\n");
}

export async function extractTextFromFile(filename: string, buffer: Buffer): Promise<string> {
  if (buffer.length > MAX_BYTES) {
    throw new Error("File is larger than 12 MB");
  }
  const ext = extensionOf(filename);
  if (TEXT_EXTENSIONS.has(ext)) {
    return buffer.toString("utf8");
  }
  if (ext === ".pdf") return extractPdf(buffer);
  if (ext === ".docx") return extractDocx(buffer);
  if (ext === ".pptx") return extractPptx(buffer);
  throw new Error(`Unsupported file type: ${ext || "unknown"}`);
}
