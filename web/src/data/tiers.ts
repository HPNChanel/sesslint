// Single source of truth for pricing. Prices are integer US cents.
// Free is the complete Apache-2.0 CLI and stays that way; Plus/Max sell
// commercial add-ons (see DEMAND.md "possible paid features"). Anything not
// yet built is marked `coming` so the page never promises unshipped work.
import type { Lang } from "../i18n";

export type TierId = "free" | "plus" | "max";
export type Status = "shipped" | "coming";

export type Tier = {
  id: TierId;
  rank: number;
  priceCents: number;
  machines: number | null; // null = unlimited
  giftable: boolean;
};

export const TIERS: Record<TierId, Tier> = {
  free: { id: "free", rank: 0, priceCents: 0, machines: null, giftable: false },
  plus: { id: "plus", rank: 1, priceCents: 900, machines: 3, giftable: true },
  max: { id: "max", rank: 2, priceCents: 4900, machines: 10, giftable: true },
};

export const TIER_ORDER: readonly TierId[] = ["free", "plus", "max"];

/** Policy knobs surfaced in the FAQ and promise strip. */
export const POLICY = {
  refundDays: 14,
  lifetimeUpdates: true,
  maxBundledPlusGifts: 1,
} as const;

type L10n = Record<Lang, string>;

export type Feature = {
  id: string;
  group: "core" | "plus" | "max" | "license";
  label: L10n;
  /** Value per tier: true/false, or a short label. */
  value: Record<TierId, boolean | L10n>;
  status: Status;
};

const all = { free: true, plus: true, max: true } as const;
const paid = { free: false, plus: true, max: true } as const;
const maxOnly = { free: false, plus: false, max: true } as const;

export const FEATURES: readonly Feature[] = [
  // Core: the full open-source CLI, identical in every tier.
  { id: "cli", group: "core", status: "shipped", value: all,
    label: { en: "Full CLI: check, triage, repair, verify, seal, watch, diff, stats, bundle…", vi: "Toàn bộ CLI: check, triage, repair, verify, seal, watch, diff, stats, bundle…" } },
  { id: "detectors", group: "core", status: "shipped", value: all,
    label: { en: "Every SL detector and conservative repair recipe", vi: "Mọi detector SL và recipe sửa lỗi an toàn" } },
  { id: "adapters", group: "core", status: "shipped", value: all,
    label: { en: "Claude Code, Codex, OpenAI Agents SDK adapters + Adapter SDK", vi: "Adapter Claude Code, Codex, OpenAI Agents SDK + Adapter SDK" } },
  { id: "formats", group: "core", status: "shipped", value: all,
    label: { en: "human / JSON / SARIF / HTML reports", vi: "Báo cáo human / JSON / SARIF / HTML" } },
  { id: "integrations", group: "core", status: "shipped", value: all,
    label: { en: "MCP server, agent hooks, GitHub Action, pre-commit", vi: "MCP server, agent hook, GitHub Action, pre-commit" } },
  { id: "portable", group: "core", status: "shipped", value: all,
    label: { en: "Signed portable binaries (Sigstore + SLSA)", vi: "Binary portable có chữ ký (Sigstore + SLSA)" } },
  { id: "support", group: "core", status: "shipped",
    value: {
      free: { en: "GitHub Issues", vi: "GitHub Issues" },
      plus: { en: "Priority triage", vi: "Triage ưu tiên" },
      max: { en: "Email, 2 business days", vi: "Email, 2 ngày làm việc" },
    },
    label: { en: "Support", vi: "Hỗ trợ" } },

  // Plus pack.
  { id: "themes", group: "plus", status: "coming", value: paid,
    label: { en: "Premium HTML report themes + print/PDF layout", vi: "Theme báo cáo HTML cao cấp + layout in/PDF" } },
  { id: "presets", group: "plus", status: "coming", value: paid,
    label: { en: "Curated CI policy presets", vi: "Preset policy CI dựng sẵn" } },
  { id: "early", group: "plus", status: "coming", value: paid,
    label: { en: "Early-access pre-release channel", vi: "Kênh early-access bản pre-release" } },
  { id: "credits", group: "plus", status: "coming", value: paid,
    label: { en: "Name in SUPPORTERS", vi: "Tên trong danh sách SUPPORTERS" } },

  // Max pack.
  { id: "policy", group: "max", status: "coming", value: maxOnly,
    label: { en: "Org policy bundles", vi: "Bộ policy cho tổ chức" } },
  { id: "attest", group: "max", status: "coming", value: maxOnly,
    label: { en: "Signed repair attestations", vi: "Attestation có chữ ký cho mỗi lần repair" } },
  { id: "fleet", group: "max", status: "coming", value: maxOnly,
    label: { en: "Fleet report: offline HTML dashboard across many sessions", vi: "Fleet report: dashboard HTML offline cho nhiều session" } },
  { id: "adapterkit", group: "max", status: "coming", value: maxOnly,
    label: { en: "Private adapter kit + one adapter review", vi: "Kit adapter riêng + 1 lần review adapter" } },
  { id: "approval", group: "max", status: "coming", value: maxOnly,
    label: { en: "Role-based approval for lossy (salvage) repairs", vi: "Duyệt repair lossy (salvage) theo vai trò" } },
  { id: "invoice", group: "max", status: "coming", value: maxOnly,
    label: { en: "Commercial invoice", vi: "Hóa đơn thương mại" } },

  // License terms.
  { id: "machines", group: "license", status: "shipped",
    value: {
      free: { en: "Unlimited", vi: "Không giới hạn" },
      plus: { en: "3 machines", vi: "3 máy" },
      max: { en: "10 machines", vi: "10 máy" },
    },
    label: { en: "Machines", vi: "Số máy" } },
  { id: "updates", group: "license", status: "shipped",
    value: {
      free: { en: "Forever", vi: "Mãi mãi" },
      plus: { en: "Lifetime", vi: "Trọn đời" },
      max: { en: "Lifetime", vi: "Trọn đời" },
    },
    label: { en: "Updates", vi: "Cập nhật" } },
  { id: "gift", group: "license", status: "coming",
    value: { free: false, plus: false, max: { en: "1 Plus gift code", vi: "1 mã quà Plus" } },
    label: { en: "Bundled gift", vi: "Quà kèm theo" } },
];

/** Headline bullets per receipt (feature ids, in order). */
export const RECEIPT_LINES: Record<TierId, readonly string[]> = {
  free: ["cli", "detectors", "adapters", "integrations", "portable"],
  plus: ["themes", "presets", "early", "credits"],
  max: ["policy", "attest", "fleet", "adapterkit", "approval", "gift"],
};
