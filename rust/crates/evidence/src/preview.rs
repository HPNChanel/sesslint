//! Structural repair preview — content-free delta list before writes (T-03).
//!
//! Port of `src/sesslint/preview.py` lines 1–251
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! ``sesslint repair IN --preview`` runs detection+planning, then renders the
//! would-be outcome as structural deltas — which events get dropped, relinked,
//! deduplicated, or tail-discarded — so the operator can approve with evidence
//! instead of trust. Preview writes nothing: it composes with ``--json`` and is
//! incompatible with every flag that produces an artifact.
//!
//! Delta rows are content-free: ``{action, event_id, kind, source_line,
//! reason_code, recipe}`` — bounded identifiers, ordinals and rule codes only,
//! never payload fields. Refusals render the same surface: blocked findings are
//! listed with their pinned code+reason so a refused preview stays informative.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::EvidenceError;

/// Python `PREVIEW_VERSION`.
pub const PREVIEW_VERSION: &str = "sesslint.preview/v1";

/// Recipe name → content-free delta action, in Python declaration order.
///
/// Unmapped recipes fail closed to `drop` (the most conservative description:
/// something is removed). Stored as a slice so lookup is equality search;
/// callers must not iterate a `HashMap` onto output.
pub const RECIPE_ACTIONS: &[(&str, &str)] = &[
    ("terminal-suffix-discard", "discard-tail"),
    ("torn-terminal-record-discard", "discard-tail"),
    ("torn-compaction-project", "discard-tail"),
    ("side-effect-unknown-truncate", "discard-tail"),
    ("identical-duplicate-collapse", "dedupe"),
    ("duplicate-projection-removal", "dedupe"),
    ("proven-unique-parent-restore", "relink"),
    ("compaction-projection-reunion", "relink"),
    ("orphan-result-drop", "drop"),
    ("torn-record-excision", "drop"),
    ("unresolvable-branch-amputate", "drop"),
    ("identical-duplicate-drop", "dedupe"),
    ("seq-renumber", "normalize"),
];

const MAX_ID: usize = 80;
const MISSING_REASON: &str = "SL000";
const DEFAULT_ACTION: &str = "drop";

/// JSON-safe value in a preview `to_dict` map.
///
/// Objects keep insertion order (`Vec` of pairs). `to_json` re-sorts keys to
/// match `json.dumps(..., sort_keys=True)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreviewJson {
    Int(i64),
    String(String),
    Array(Vec<PreviewJson>),
    Object(Vec<(String, PreviewJson)>),
}

/// One structural would-be change (content-free).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewDelta {
    pub action: String,
    pub reason_code: String,
    pub recipe: String,
    pub event_id: Option<String>,
    pub kind: Option<String>,
    pub source_line: Option<i64>,
    pub seq: i64,
}

impl PreviewDelta {
    /// Python `PreviewDelta.to_dict` — insertion order, no `seq`.
    pub fn to_dict(&self) -> PreviewJson {
        let mut pairs = vec![
            (
                "action".to_owned(),
                PreviewJson::String(self.action.clone()),
            ),
            (
                "reason_code".to_owned(),
                PreviewJson::String(self.reason_code.clone()),
            ),
            (
                "recipe".to_owned(),
                PreviewJson::String(self.recipe.clone()),
            ),
        ];
        if let Some(event_id) = &self.event_id {
            pairs.push(("event_id".to_owned(), PreviewJson::String(event_id.clone())));
        }
        if let Some(kind) = &self.kind {
            pairs.push(("kind".to_owned(), PreviewJson::String(kind.clone())));
        }
        if let Some(source_line) = self.source_line {
            pairs.push(("source_line".to_owned(), PreviewJson::Int(source_line)));
        }
        PreviewJson::Object(pairs)
    }
}

/// A finding the plan could not address (code+reason only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewBlocked {
    pub code: String,
    pub reason: String,
    pub finding_fp: String,
}

impl PreviewBlocked {
    /// Python `PreviewBlocked.to_dict` keys: `code`, `finding_fp`, `reason`.
    pub fn to_dict(&self) -> PreviewJson {
        PreviewJson::Object(vec![
            ("code".to_owned(), PreviewJson::String(self.code.clone())),
            (
                "finding_fp".to_owned(),
                PreviewJson::String(self.finding_fp.clone()),
            ),
            (
                "reason".to_owned(),
                PreviewJson::String(self.reason.clone()),
            ),
        ])
    }
}

/// Content-free preview document (`sesslint.preview/v1`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewDoc {
    pub source: String,
    pub steps: Vec<PreviewDelta>,
    pub blocked: Vec<PreviewBlocked>,
    pub plan_fingerprint: String,
    pub policy: String,
    pub version: String,
}

impl PreviewDoc {
    /// Construct a document with [`PREVIEW_VERSION`].
    pub fn new(
        source: String,
        steps: Vec<PreviewDelta>,
        blocked: Vec<PreviewBlocked>,
        plan_fingerprint: String,
        policy: String,
    ) -> Self {
        Self {
            source,
            steps,
            blocked,
            plan_fingerprint,
            policy,
            version: PREVIEW_VERSION.to_owned(),
        }
    }

    /// Preview represents a refusal surface (blocked findings present).
    pub fn refused(&self) -> bool {
        !self.blocked.is_empty()
    }

    /// Python `PreviewDoc.to_dict`.
    ///
    /// `counts` is a `Vec` of pairs in first-seen action order after the
    /// plan-order sort — not a `HashMap` / `BTreeMap` iteration.
    pub fn to_dict(&self) -> PreviewJson {
        let mut counts: Vec<(String, i64)> = Vec::new();
        for delta in &self.steps {
            match counts
                .iter_mut()
                .find(|(action, _)| action == &delta.action)
            {
                Some((_, n)) => *n += 1,
                None => counts.push((delta.action.clone(), 1)),
            }
        }
        let counts_object = PreviewJson::Object(
            counts
                .into_iter()
                .map(|(action, n)| (action, PreviewJson::Int(n)))
                .collect(),
        );
        PreviewJson::Object(vec![
            (
                "blocked".to_owned(),
                PreviewJson::Array(self.blocked.iter().map(PreviewBlocked::to_dict).collect()),
            ),
            ("counts".to_owned(), counts_object),
            (
                "plan_fingerprint".to_owned(),
                PreviewJson::String(self.plan_fingerprint.clone()),
            ),
            (
                "policy".to_owned(),
                PreviewJson::String(self.policy.clone()),
            ),
            (
                "schema".to_owned(),
                PreviewJson::String(self.version.clone()),
            ),
            (
                "source".to_owned(),
                PreviewJson::String(self.source.clone()),
            ),
            (
                "steps".to_owned(),
                PreviewJson::Array(self.steps.iter().map(PreviewDelta::to_dict).collect()),
            ),
        ])
    }

    /// `json.dumps(self.to_dict(), indent=2, sort_keys=True)` with default
    /// `ensure_ascii=True`.
    pub fn to_json(&self) -> String {
        dumps_indent2_sorted(&self.to_dict())
    }

    /// Human renderer. Missing identifiers print as `-`; missing lines as
    /// `line -`.
    pub fn render_human(&self) -> String {
        let mut lines = vec![
            format!("Preview: {}", self.source),
            format!(
                "  plan fingerprint: {}  policy: {}",
                self.plan_fingerprint, self.policy
            ),
        ];
        if self.steps.is_empty() && self.blocked.is_empty() {
            lines.push("  no changes planned".to_owned());
        }
        if !self.steps.is_empty() {
            lines.push(format!("  steps ({}):", self.steps.len()));
            for delta in &self.steps {
                let ident = dash_or(delta.event_id.as_deref());
                let loc = match delta.source_line {
                    Some(line) => format!("line {line}"),
                    None => "line -".to_owned(),
                };
                let kind = dash_or(delta.kind.as_deref());
                lines.push(format!(
                    "    {}: {} ({}, {}) [{}]",
                    delta.action, ident, kind, loc, delta.reason_code
                ));
            }
        }
        if !self.blocked.is_empty() {
            lines.push(format!("  blocked ({}):", self.blocked.len()));
            for blocked in &self.blocked {
                lines.push(format!("    [{}] {}", blocked.code, blocked.reason));
            }
        }
        lines.join("\n")
    }
}

/// Bounded identifier echo: strings only, length-capped, never payloads.
///
/// Python `_bounded_id`. Only a non-empty string is echoed; anything else is
/// `None`. Cap is 80 Unicode scalar values.
pub fn bounded_id(value: Option<&str>) -> Option<String> {
    let value = value.filter(|text| !text.is_empty())?;
    Some(value.chars().take(MAX_ID).collect())
}

/// Fields `_deltas_for_plan` reads from a Python `RepairPlan`.
///
/// `RepairPlan` is not a ported Rust type. This view lives here so the repair
/// crate is not given a fake plan type.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PreviewPlanInput {
    pub steps: Vec<PreviewStepInput>,
}

/// One plan step: recipe, target finding, optional event index, seq.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewStepInput {
    pub recipe: String,
    pub target_finding_fp: String,
    pub target_index: Option<i64>,
    pub seq: i64,
}

/// Finding fields read while mapping deltas.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewFindingInput {
    pub fingerprint: String,
    pub code: String,
    pub source: Option<PreviewSourceInput>,
}

/// `finding.source.line` / `record_id`. `line` is `None` when Python would
/// see a non-int (including `bool`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewSourceInput {
    pub line: Option<i64>,
    pub record_id: Option<String>,
}

/// Event fields read while mapping deltas (`id`, `kind` only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewEventInput {
    pub id: Option<String>,
    pub kind: Option<String>,
}

/// Map plan steps to content-free delta rows (plan order, then action/line).
///
/// Python `_deltas_for_plan`. Duplicate fingerprints: the last finding wins.
/// `bool` is not an int (`None` here). `source_line` only when `line` is an
/// int ≥ 1. Event index only when it is an int inside the event slice.
pub fn deltas_for_plan(
    plan: &PreviewPlanInput,
    findings: &[PreviewFindingInput],
    events: &[PreviewEventInput],
) -> Vec<PreviewDelta> {
    let mut fp_map: BTreeMap<&str, &PreviewFindingInput> = BTreeMap::new();
    for finding in findings {
        fp_map.insert(finding.fingerprint.as_str(), finding);
    }
    let mut rows = Vec::new();
    for step in &plan.steps {
        let action = action_for_recipe(&step.recipe).to_owned();
        let finding = fp_map.get(step.target_finding_fp.as_str()).copied();
        let reason_code = match finding {
            Some(found) => found.code.clone(),
            None => MISSING_REASON.to_owned(),
        };
        let source_line = finding
            .and_then(|found| found.source.as_ref())
            .and_then(|source| source.line)
            .filter(|line| *line >= 1);
        let mut event_id = None;
        let mut kind = None;
        if let Some(idx) = step
            .target_index
            .and_then(|idx| usize::try_from(idx).ok())
            .filter(|idx| *idx < events.len())
        {
            let event = &events[idx];
            event_id = bounded_id(event.id.as_deref());
            kind = bounded_id(event.kind.as_deref());
        }
        if event_id.is_none() {
            event_id = finding
                .and_then(|found| found.source.as_ref())
                .and_then(|source| bounded_id(source.record_id.as_deref()));
        }
        rows.push(PreviewDelta {
            action,
            reason_code,
            recipe: step.recipe.clone(),
            event_id,
            kind,
            source_line,
            seq: step.seq,
        });
    }
    rows.sort_by(|left, right| {
        left.seq
            .cmp(&right.seq)
            .then_with(|| left.action.cmp(&right.action))
            .then_with(|| {
                left.source_line
                    .unwrap_or(0)
                    .cmp(&right.source_line.unwrap_or(0))
            })
    });
    rows
}

/// Compute the structural repair preview for `source_path` (no writes).
///
/// Python late-imports `sesslint.batch._plan_detail` and
/// `sesslint.report.minimize_path`. Those symbols are not ported, so this
/// function does not invent a plan or a minimized path.
pub fn repair_preview(
    _source_path: &Path,
    _format: Option<&str>,
    _policy: &str,
    _profile: &str,
    _acknowledge_side_effects: bool,
) -> Result<PreviewDoc, EvidenceError> {
    Err(EvidenceError::Unsupported)
}

/// Return the packaged `sesslint.preview/v1` JSON Schema path.
///
/// Python late-imports `sesslint._resources.schema_path`. That symbol is not
/// ported, so this function does not invent a path and does not read `schemas/`.
pub fn get_preview_schema_path() -> Result<PathBuf, EvidenceError> {
    Err(EvidenceError::Unsupported)
}

/// Load the `sesslint.preview/v1` JSON Schema document.
///
/// Does not invent a schema document and does not read `schemas/` as a
/// substitute.
pub fn load_preview_schema() -> Result<PreviewJson, EvidenceError> {
    Err(EvidenceError::Unsupported)
}

fn action_for_recipe(recipe: &str) -> &'static str {
    for (name, action) in RECIPE_ACTIONS {
        if *name == recipe {
            return action;
        }
    }
    DEFAULT_ACTION
}

fn dash_or(value: Option<&str>) -> &str {
    match value {
        Some(text) if !text.is_empty() => text,
        _ => "-",
    }
}

fn dumps_indent2_sorted(value: &PreviewJson) -> String {
    let mut out = String::new();
    write_json(&mut out, value, 0, true);
    out
}

fn write_json(out: &mut String, value: &PreviewJson, indent: usize, sort_keys: bool) {
    match value {
        PreviewJson::Int(number) => out.push_str(&number.to_string()),
        PreviewJson::String(text) => push_json_string(out, text),
        PreviewJson::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            let inner = indent + 2;
            for (index, item) in items.iter().enumerate() {
                out.push('\n');
                push_spaces(out, inner);
                write_json(out, item, inner, sort_keys);
                if index + 1 != items.len() {
                    out.push(',');
                }
            }
            out.push('\n');
            push_spaces(out, indent);
            out.push(']');
        }
        PreviewJson::Object(pairs) => {
            if pairs.is_empty() {
                out.push_str("{}");
                return;
            }
            let mut order: Vec<usize> = (0..pairs.len()).collect();
            if sort_keys {
                order.sort_by(|&left, &right| pairs[left].0.cmp(&pairs[right].0));
            }
            out.push('{');
            let inner = indent + 2;
            for (index, pair_index) in order.iter().enumerate() {
                let (key, nested) = &pairs[*pair_index];
                out.push('\n');
                push_spaces(out, inner);
                push_json_string(out, key);
                out.push_str(": ");
                write_json(out, nested, inner, sort_keys);
                if index + 1 != order.len() {
                    out.push(',');
                }
            }
            out.push('\n');
            push_spaces(out, indent);
            out.push('}');
        }
    }
}

fn push_spaces(out: &mut String, count: usize) {
    for _ in 0..count {
        out.push(' ');
    }
}

/// `json.dumps` string with default `ensure_ascii=True`.
fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => {
                let code = c as u32;
                if code < 0x20 || code == 0x7f {
                    push_unicode_escape(out, code);
                } else if code >= 0x80 {
                    if code <= 0xFFFF {
                        push_unicode_escape(out, code);
                    } else {
                        let payload = code - 0x1_0000;
                        let high = 0xD800 + (payload >> 10);
                        let low = 0xDC00 + (payload & 0x3FF);
                        push_unicode_escape(out, high);
                        push_unicode_escape(out, low);
                    }
                } else {
                    out.push(c);
                }
            }
        }
    }
    out.push('"');
}

fn push_unicode_escape(out: &mut String, code: u32) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str("\\u");
    out.push(char::from(HEX[((code >> 12) & 0xF) as usize]));
    out.push(char::from(HEX[((code >> 8) & 0xF) as usize]));
    out.push(char::from(HEX[((code >> 4) & 0xF) as usize]));
    out.push(char::from(HEX[(code & 0xF) as usize]));
}

#[cfg(test)]
mod tests {
    use super::{
        action_for_recipe, bounded_id, deltas_for_plan, get_preview_schema_path,
        load_preview_schema, repair_preview, PreviewBlocked, PreviewDelta, PreviewDoc,
        PreviewEventInput, PreviewFindingInput, PreviewJson, PreviewPlanInput, PreviewSourceInput,
        PreviewStepInput, PREVIEW_VERSION, RECIPE_ACTIONS,
    };
    use crate::EvidenceError;
    use std::path::Path;

    const SYNTHETIC_SOURCE: &str = "synthetic-preview.jsonl";
    const SYNTHETIC_FP: &str = "fp-synth-aaaa";
    const SYNTHETIC_FP_LATE: &str = "fp-synth-bbbb";
    const SYNTHETIC_EVENT: &str = "ev-synth-01";
    const SYNTHETIC_KIND: &str = "message";
    const SYNTHETIC_CODE: &str = "SL003";
    const SYNTHETIC_REASON: &str = "synthetic-refuse";
    const SYNTHETIC_PLAN_FP: &str = "plan-fp-synth";
    const SYNTHETIC_POLICY: &str = "conservative";
    const SYNTHETIC_RECORD: &str = "rec-synth-01";

    fn step(
        recipe: &str,
        target_finding_fp: &str,
        target_index: Option<i64>,
        seq: i64,
    ) -> PreviewStepInput {
        PreviewStepInput {
            recipe: recipe.to_owned(),
            target_finding_fp: target_finding_fp.to_owned(),
            target_index,
            seq,
        }
    }

    fn finding(
        fingerprint: &str,
        code: &str,
        line: Option<i64>,
        record_id: Option<&str>,
    ) -> PreviewFindingInput {
        PreviewFindingInput {
            fingerprint: fingerprint.to_owned(),
            code: code.to_owned(),
            source: Some(PreviewSourceInput {
                line,
                record_id: record_id.map(str::to_owned),
            }),
        }
    }

    fn event(id: Option<&str>, kind: Option<&str>) -> PreviewEventInput {
        PreviewEventInput {
            id: id.map(str::to_owned),
            kind: kind.map(str::to_owned),
        }
    }

    fn object_keys(value: &PreviewJson) -> Vec<&str> {
        match value {
            PreviewJson::Object(pairs) => pairs.iter().map(|(key, _)| key.as_str()).collect(),
            PreviewJson::Int(_) | PreviewJson::String(_) | PreviewJson::Array(_) => Vec::new(),
        }
    }

    fn object_get<'a>(value: &'a PreviewJson, key: &str) -> Option<&'a PreviewJson> {
        match value {
            PreviewJson::Object(pairs) => pairs
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, nested)| nested),
            PreviewJson::Int(_) | PreviewJson::String(_) | PreviewJson::Array(_) => None,
        }
    }

    #[test]
    fn bounded_id_rejects_empty_and_missing() {
        assert_eq!(bounded_id(None), None);
        assert_eq!(bounded_id(Some("")), None);
        assert_eq!(
            bounded_id(Some(SYNTHETIC_EVENT)),
            Some(SYNTHETIC_EVENT.to_owned())
        );
    }

    #[test]
    fn bounded_id_caps_at_eighty_scalars() {
        let eighty: String = "a".repeat(80);
        let eighty_one: String = "a".repeat(81);
        assert_eq!(bounded_id(Some(&eighty)), Some(eighty.clone()));
        assert_eq!(bounded_id(Some(&eighty_one)), Some(eighty));
        let wide: String = "é".repeat(81);
        let wide_cap: String = "é".repeat(80);
        assert_eq!(bounded_id(Some(&wide)), Some(wide_cap));
    }

    #[test]
    fn recipe_actions_declaration_order_and_unknown_drop() {
        let names: Vec<&str> = RECIPE_ACTIONS.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            vec![
                "terminal-suffix-discard",
                "torn-terminal-record-discard",
                "torn-compaction-project",
                "side-effect-unknown-truncate",
                "identical-duplicate-collapse",
                "duplicate-projection-removal",
                "proven-unique-parent-restore",
                "compaction-projection-reunion",
                "orphan-result-drop",
                "torn-record-excision",
                "unresolvable-branch-amputate",
                "identical-duplicate-drop",
                "seq-renumber",
            ]
        );
        assert_eq!(action_for_recipe("identical-duplicate-collapse"), "dedupe");
        assert_eq!(action_for_recipe("seq-renumber"), "normalize");
        assert_eq!(action_for_recipe("brand-new-recipe"), "drop");
    }

    #[test]
    fn deltas_happy_path_maps_recipe_event_and_line() {
        let plan = PreviewPlanInput {
            steps: vec![
                step("identical-duplicate-collapse", SYNTHETIC_FP, Some(0), 0),
                step("seq-renumber", SYNTHETIC_FP, Some(0), 1),
            ],
        };
        let findings = vec![finding(
            SYNTHETIC_FP,
            SYNTHETIC_CODE,
            Some(4),
            Some(SYNTHETIC_RECORD),
        )];
        let events = vec![event(Some(SYNTHETIC_EVENT), Some(SYNTHETIC_KIND))];
        let deltas = deltas_for_plan(&plan, &findings, &events);
        assert_eq!(deltas.len(), 2);
        assert_eq!(deltas[0].action, "dedupe");
        assert_eq!(deltas[0].reason_code, SYNTHETIC_CODE);
        assert_eq!(deltas[0].event_id.as_deref(), Some(SYNTHETIC_EVENT));
        assert_eq!(deltas[0].kind.as_deref(), Some(SYNTHETIC_KIND));
        assert_eq!(deltas[0].source_line, Some(4));
        assert_eq!(deltas[1].action, "normalize");
        assert_eq!(deltas[1].recipe, "seq-renumber");
    }

    #[test]
    fn unknown_recipe_fails_closed_to_drop() {
        let plan = PreviewPlanInput {
            steps: vec![step("brand-new-recipe", "fp", None, 0)],
        };
        let deltas = deltas_for_plan(&plan, &[], &[]);
        assert_eq!(deltas[0].action, "drop");
        assert_eq!(deltas[0].reason_code, "SL000");
        assert_eq!(deltas[0].recipe, "brand-new-recipe");
    }

    #[test]
    fn missing_finding_uses_sl000() {
        let plan = PreviewPlanInput {
            steps: vec![step("orphan-result-drop", "missing-fp", None, 0)],
        };
        let deltas = deltas_for_plan(&plan, &[], &[]);
        assert_eq!(deltas[0].reason_code, "SL000");
        assert_eq!(deltas[0].action, "drop");
    }

    #[test]
    fn duplicate_fingerprint_last_finding_wins() {
        let plan = PreviewPlanInput {
            steps: vec![step("orphan-result-drop", SYNTHETIC_FP, None, 0)],
        };
        let findings = vec![
            finding(SYNTHETIC_FP, "SL001", Some(1), None),
            finding(SYNTHETIC_FP, SYNTHETIC_CODE, Some(9), None),
        ];
        let deltas = deltas_for_plan(&plan, &findings, &[]);
        assert_eq!(deltas[0].reason_code, SYNTHETIC_CODE);
        assert_eq!(deltas[0].source_line, Some(9));
    }

    #[test]
    fn source_line_requires_int_at_least_one() {
        let plan = PreviewPlanInput {
            steps: vec![
                step("orphan-result-drop", "fp-a", None, 0),
                step("orphan-result-drop", "fp-b", None, 1),
                step("orphan-result-drop", "fp-c", None, 2),
                step("orphan-result-drop", "fp-d", None, 3),
            ],
        };
        let findings = vec![
            finding("fp-a", "SL001", None, None),
            finding("fp-b", "SL001", Some(0), None),
            finding("fp-c", "SL001", Some(-3), None),
            finding("fp-d", "SL001", Some(2), None),
        ];
        let deltas = deltas_for_plan(&plan, &findings, &[]);
        assert_eq!(deltas[0].source_line, None);
        assert_eq!(deltas[1].source_line, None);
        assert_eq!(deltas[2].source_line, None);
        assert_eq!(deltas[3].source_line, Some(2));
    }

    #[test]
    fn event_index_requires_int_inside_slice() {
        let plan = PreviewPlanInput {
            steps: vec![
                step("orphan-result-drop", SYNTHETIC_FP, None, 0),
                step("orphan-result-drop", SYNTHETIC_FP, Some(-1), 1),
                step("orphan-result-drop", SYNTHETIC_FP, Some(1), 2),
                step("orphan-result-drop", SYNTHETIC_FP, Some(0), 3),
            ],
        };
        let findings = vec![finding(SYNTHETIC_FP, SYNTHETIC_CODE, Some(1), None)];
        let events = vec![event(Some(SYNTHETIC_EVENT), Some(SYNTHETIC_KIND))];
        let deltas = deltas_for_plan(&plan, &findings, &events);
        assert_eq!(deltas[0].event_id, None);
        assert_eq!(deltas[0].kind, None);
        assert_eq!(deltas[1].event_id, None);
        assert_eq!(deltas[2].event_id, None);
        assert_eq!(deltas[3].event_id.as_deref(), Some(SYNTHETIC_EVENT));
        assert_eq!(deltas[3].kind.as_deref(), Some(SYNTHETIC_KIND));
    }

    #[test]
    fn event_id_falls_back_to_record_id() {
        let plan = PreviewPlanInput {
            steps: vec![step("orphan-result-drop", SYNTHETIC_FP, Some(0), 0)],
        };
        let findings = vec![finding(
            SYNTHETIC_FP,
            SYNTHETIC_CODE,
            Some(1),
            Some(SYNTHETIC_RECORD),
        )];
        let events = vec![event(Some(""), Some(SYNTHETIC_KIND))];
        let deltas = deltas_for_plan(&plan, &findings, &events);
        assert_eq!(deltas[0].event_id.as_deref(), Some(SYNTHETIC_RECORD));
        assert_eq!(deltas[0].kind.as_deref(), Some(SYNTHETIC_KIND));
    }

    #[test]
    fn sort_is_seq_then_action_then_source_line() {
        let plan = PreviewPlanInput {
            steps: vec![
                step("seq-renumber", "fp-n", None, 1),
                step("orphan-result-drop", "fp-high", None, 1),
                step("orphan-result-drop", "fp-low", None, 1),
                step("identical-duplicate-collapse", SYNTHETIC_FP, None, 0),
            ],
        };
        let findings = vec![
            finding("fp-n", "SL001", None, None),
            finding("fp-high", "SL001", Some(9), None),
            finding("fp-low", "SL001", Some(3), None),
            finding(SYNTHETIC_FP, SYNTHETIC_CODE, None, None),
        ];
        let deltas = deltas_for_plan(&plan, &findings, &[]);
        let keys: Vec<(&str, i64, i64)> = deltas
            .iter()
            .map(|row| (row.action.as_str(), row.seq, row.source_line.unwrap_or(0)))
            .collect();
        assert_eq!(
            keys,
            vec![
                ("dedupe", 0, 0),
                ("drop", 1, 3),
                ("drop", 1, 9),
                ("normalize", 1, 0)
            ]
        );
    }

    #[test]
    fn delta_to_dict_omits_seq_and_absent_optionals() {
        let sparse = PreviewDelta {
            action: "drop".to_owned(),
            reason_code: "SL000".to_owned(),
            recipe: "brand-new-recipe".to_owned(),
            event_id: None,
            kind: None,
            source_line: None,
            seq: 7,
        };
        let dict = sparse.to_dict();
        assert_eq!(object_keys(&dict), vec!["action", "reason_code", "recipe"]);
        assert!(object_get(&dict, "seq").is_none());
        let full = PreviewDelta {
            event_id: Some(SYNTHETIC_EVENT.to_owned()),
            kind: Some(SYNTHETIC_KIND.to_owned()),
            source_line: Some(4),
            ..sparse
        };
        assert_eq!(
            object_keys(&full.to_dict()),
            vec![
                "action",
                "reason_code",
                "recipe",
                "event_id",
                "kind",
                "source_line"
            ]
        );
    }

    #[test]
    fn blocked_to_dict_key_order() {
        let blocked = PreviewBlocked {
            code: "SL203".to_owned(),
            reason: SYNTHETIC_REASON.to_owned(),
            finding_fp: SYNTHETIC_FP.to_owned(),
        };
        assert_eq!(
            object_keys(&blocked.to_dict()),
            vec!["code", "finding_fp", "reason"]
        );
    }

    #[test]
    fn counts_first_seen_after_sort_not_alphabetical() {
        let doc = PreviewDoc::new(
            SYNTHETIC_SOURCE.to_owned(),
            vec![
                PreviewDelta {
                    action: "normalize".to_owned(),
                    reason_code: "SL000".to_owned(),
                    recipe: "seq-renumber".to_owned(),
                    event_id: None,
                    kind: None,
                    source_line: None,
                    seq: 0,
                },
                PreviewDelta {
                    action: "drop".to_owned(),
                    reason_code: "SL000".to_owned(),
                    recipe: "orphan-result-drop".to_owned(),
                    event_id: None,
                    kind: None,
                    source_line: None,
                    seq: 1,
                },
            ],
            Vec::new(),
            SYNTHETIC_PLAN_FP.to_owned(),
            SYNTHETIC_POLICY.to_owned(),
        );
        let dict = doc.to_dict();
        let counts = object_get(&dict, "counts").expect("counts");
        assert_eq!(object_keys(counts), vec!["normalize", "drop"]);
        let json = doc.to_json();
        assert!(json.contains("\"counts\": {\n    \"drop\": 1,\n    \"normalize\": 1\n  }"));
    }

    #[test]
    fn to_json_matches_python_indent_sort_keys_ensure_ascii() {
        let doc = PreviewDoc::new(
            SYNTHETIC_SOURCE.to_owned(),
            vec![PreviewDelta {
                action: "drop".to_owned(),
                reason_code: "SL000".to_owned(),
                recipe: "brand-new-recipe".to_owned(),
                event_id: Some(SYNTHETIC_EVENT.to_owned()),
                kind: Some(SYNTHETIC_KIND.to_owned()),
                source_line: Some(3),
                seq: 1,
            }],
            vec![PreviewBlocked {
                code: "SL203".to_owned(),
                reason: "café".to_owned(),
                finding_fp: SYNTHETIC_FP.to_owned(),
            }],
            SYNTHETIC_PLAN_FP.to_owned(),
            SYNTHETIC_POLICY.to_owned(),
        );
        assert_eq!(
            doc.to_json(),
            "{\n  \"blocked\": [\n    {\n      \"code\": \"SL203\",\n      \"finding_fp\": \"fp-synth-aaaa\",\n      \"reason\": \"caf\\u00e9\"\n    }\n  ],\n  \"counts\": {\n    \"drop\": 1\n  },\n  \"plan_fingerprint\": \"plan-fp-synth\",\n  \"policy\": \"conservative\",\n  \"schema\": \"sesslint.preview/v1\",\n  \"source\": \"synthetic-preview.jsonl\",\n  \"steps\": [\n    {\n      \"action\": \"drop\",\n      \"event_id\": \"ev-synth-01\",\n      \"kind\": \"message\",\n      \"reason_code\": \"SL000\",\n      \"recipe\": \"brand-new-recipe\",\n      \"source_line\": 3\n    }\n  ]\n}"
        );
        assert_eq!(doc.version, PREVIEW_VERSION);
        assert!(doc.refused());
    }

    #[test]
    fn render_human_uses_dashes_for_missing_fields() {
        let empty = PreviewDoc::new(
            SYNTHETIC_SOURCE.to_owned(),
            Vec::new(),
            Vec::new(),
            SYNTHETIC_PLAN_FP.to_owned(),
            SYNTHETIC_POLICY.to_owned(),
        );
        assert_eq!(
            empty.render_human(),
            "Preview: synthetic-preview.jsonl\n  plan fingerprint: plan-fp-synth  policy: conservative\n  no changes planned"
        );
        let sparse = PreviewDoc::new(
            SYNTHETIC_SOURCE.to_owned(),
            vec![PreviewDelta {
                action: "drop".to_owned(),
                reason_code: "SL000".to_owned(),
                recipe: "brand-new-recipe".to_owned(),
                event_id: None,
                kind: None,
                source_line: None,
                seq: 0,
            }],
            vec![PreviewBlocked {
                code: "SL203".to_owned(),
                reason: SYNTHETIC_REASON.to_owned(),
                finding_fp: SYNTHETIC_FP.to_owned(),
            }],
            SYNTHETIC_PLAN_FP.to_owned(),
            SYNTHETIC_POLICY.to_owned(),
        );
        assert_eq!(
            sparse.render_human(),
            "Preview: synthetic-preview.jsonl\n  plan fingerprint: plan-fp-synth  policy: conservative\n  steps (1):\n    drop: - (-, line -) [SL000]\n  blocked (1):\n    [SL203] synthetic-refuse"
        );
        assert!(!empty.refused());
        assert!(sparse.refused());
    }

    #[test]
    fn unported_entry_points_return_unsupported() {
        let preview = repair_preview(
            Path::new(SYNTHETIC_SOURCE),
            None,
            SYNTHETIC_POLICY,
            "neutral",
            false,
        );
        assert!(matches!(preview, Err(EvidenceError::Unsupported)));
        assert!(matches!(
            get_preview_schema_path(),
            Err(EvidenceError::Unsupported)
        ));
        assert!(matches!(
            load_preview_schema(),
            Err(EvidenceError::Unsupported)
        ));
    }

    #[test]
    fn deltas_do_not_copy_payload_fields() {
        let plan = PreviewPlanInput {
            steps: vec![step(
                "identical-duplicate-collapse",
                SYNTHETIC_FP_LATE,
                Some(0),
                0,
            )],
        };
        let findings = vec![finding(SYNTHETIC_FP_LATE, SYNTHETIC_CODE, Some(1), None)];
        let events = vec![event(Some(SYNTHETIC_EVENT), Some(SYNTHETIC_KIND))];
        let json = PreviewDoc::new(
            SYNTHETIC_SOURCE.to_owned(),
            deltas_for_plan(&plan, &findings, &events),
            Vec::new(),
            SYNTHETIC_PLAN_FP.to_owned(),
            SYNTHETIC_POLICY.to_owned(),
        )
        .to_json();
        assert!(!json.contains("payload"));
        assert!(!json.contains("content"));
    }
}
