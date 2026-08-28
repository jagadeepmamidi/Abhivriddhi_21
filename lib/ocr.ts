import sharp from "sharp";
import { createWorker } from "tesseract.js";
import { SENSITIVE_IMAGE_PATTERNS } from "@/lib/image-patterns";

export type ImageRedactResult = {
  mime: "image/png";
  buffer: Buffer;
  matches: number;
};

export async function redactImageBuffer(buffer: Buffer): Promise<ImageRedactResult> {
  const worker = await createWorker("eng");
  try {
    const { data } = await worker.recognize(buffer, {}, { blocks: true, text: true });
    const image = sharp(buffer);
    const meta = await image.metadata();
    const width = meta.width ?? 0;
    const height = meta.height ?? 0;
    const words =
      data.blocks?.flatMap((block) =>
        block.paragraphs.flatMap((paragraph) => paragraph.lines.flatMap((line) => line.words)),
      ) ?? [];
    const hits = words.filter((word) =>
      SENSITIVE_IMAGE_PATTERNS.some((pattern) => pattern.test(word.text)),
    );
    if (!hits.length || !width || !height) {
      const png = await image.png().toBuffer();
      return { mime: "image/png", buffer: png, matches: 0 };
    }
    const rects = hits
      .map((word) => {
        const box = word.bbox;
        const x = Math.max(0, box.x0);
        const y = Math.max(0, box.y0);
        const w = Math.max(1, box.x1 - box.x0);
        const h = Math.max(1, box.y1 - box.y0);
        return `<rect x="${x}" y="${y}" width="${w}" height="${h}" fill="#111813"/>`;
      })
      .join("");
    const svg = `<svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">${rects}</svg>`;
    const png = await image
      .composite([{ input: Buffer.from(svg), top: 0, left: 0 }])
      .png()
      .toBuffer();
    return { mime: "image/png", buffer: png, matches: hits.length };
  } finally {
    await worker.terminate();
  }
}
