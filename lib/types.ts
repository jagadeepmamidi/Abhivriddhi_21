export const ENTITY_TYPES = [
  "PERSON",
  "ORG",
  "GPE",
  "LOC",
  "DATE",
  "EMAIL",
  "PHONE",
  "SSN",
  "CREDIT_CARD",
  "BANK_ACCOUNT",
  "MONEY",
  "CUSTOM",
] as const;

export type EntityType = (typeof ENTITY_TYPES)[number];

export const PROTECTION_METHODS = [
  "redaction",
  "masking",
  "anonymization",
  "domain",
] as const;

export type ProtectionMethod = (typeof PROTECTION_METHODS)[number];

export const REDACTION_LEVELS = ["high", "medium", "low"] as const;
export type RedactionLevel = (typeof REDACTION_LEVELS)[number];

export const DOMAINS = ["general", "financial", "personal", "health"] as const;
export type Domain = (typeof DOMAINS)[number];

export type DetectedSpan = {
  start: number;
  end: number;
  type: EntityType;
  text: string;
};

export type ProtectOptions = {
  method: ProtectionMethod;
  entityTypes: EntityType[];
  customWords?: string[];
  redactionLevel?: RedactionLevel;
  domain?: Domain;
  useNer?: boolean;
};

export type ProtectResult = {
  original: string;
  processed: string;
  spans: DetectedSpan[];
  counts: Record<string, number>;
};

export type PublicUser = {
  id: string;
  username: string;
  email: string;
};
