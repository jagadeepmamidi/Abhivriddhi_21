export const SENSITIVE_IMAGE_PATTERNS: RegExp[] = [
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
  /\b\d{3}-\d{2}-\d{4}\b/,
  /\b(?:\d{4}[ -]?){3}\d{4}\b/,
  /\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/,
  /\b[A-Z][a-z]+\s[A-Z][a-z]+\b/,
];
