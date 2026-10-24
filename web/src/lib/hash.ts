// Build-time display hashes (receipts, ledger blocks). Not signatures.
import { createHash } from "node:crypto";

export function sha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

export function shortHash(hex: string, n = 12): string {
  return hex.slice(0, n);
}
