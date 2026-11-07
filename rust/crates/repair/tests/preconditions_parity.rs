//! Parity for `sesslint.repair.preconditions` against pinned Python vectors.

use model::codes::{Repairability, Severity};
use model::events::{EventField, EventMapping, EventValue};
use model::finding::{
    Finding, FindingInput, PyValue, SourceLine, SourceRef, SCHEMA_VERSION,
};
use repair::preconditions::{
    _find_component_indices, _find_torn_compaction_dropped_indices, acknowledge_side_effects,
    adjacent_identical_duplicate, branch_has_no_checkpoint, check_preconditions,
    duplicate_projection_identical, no_prior_safe_tool_after_cut, no_sl203,
    precondition_func_names, register_precondition, repairability_is_safe_auto,
    repairability_is_salvage, salvage_policy, side_effects_known, single_boundary_split,
    sl003_identical_duplicate, sl108_present, source_hash_pinned, torn_terminal_record,
    unique_parent_candidate, PreconditionContext, PreconditionError,
    FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE, MUST_ABSTAIN_UNAVAILABLE,
};
use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;

const VECTORS_REL: &str = "../../parity/vectors/repair.preconditions/vectors.json";
const EXPECTED_VECTOR_COUNT: usize = 37;
const EXPECTED_VECTORS_SHA256: &str =
    "b21cc48aad68a7cc28527fb753f98c6ca0a6e805ba209f896860f10694d35b04";

#[derive(Debug, Clone)]
struct VectorCase {
    id: String,
    construct: Vec<(String, JsonValue)>,
    expected: Vec<(String, JsonValue)>,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(VECTORS_REL)
}

#[test]
fn preconditions_module_parity_vectors() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = raw.replace("\r\n", "\n");
    let digest = sha256_hex(normalized.as_bytes());
    assert_eq!(
        digest, EXPECTED_VECTORS_SHA256,
        "vectors.json sha256 must match generator"
    );
    let cases = parse_document(&normalized).unwrap_or_else(|err| panic!("parse vectors.json: {err}"));
    assert_eq!(
        cases.len(),
        EXPECTED_VECTOR_COUNT,
        "unexpected vector count"
    );
    for case in &cases {
        assert_case(case);
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(&sha256(bytes))
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(nibble(byte >> 4));
            out.push(nibble(byte & 0x0f));
        }
        out
    }

    fn nibble(value: u8) -> char {
        match value {
            0..=9 => char::from(b'0' + value),
            10..=15 => char::from(b'a' + value - 10),
            _ => '?',
        }
    }
}

#[allow(clippy::too_many_lines)]
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h = [
        0x6a09e667_u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0_u32; 64];
        for (idx, word) in chunk.chunks(4).enumerate().take(16) {
            w[idx] = u32::from_be_bytes(word.try_into().unwrap());
        }
        for idx in 16..64 {
            let s0 = w[idx - 15].rotate_right(7) ^ w[idx - 15].rotate_right(18) ^ (w[idx - 15] >> 3);
            let s1 = w[idx - 2].rotate_right(17) ^ w[idx - 2].rotate_right(19) ^ (w[idx - 2] >> 10);
            w[idx] = w[idx - 16]
                .wrapping_add(s0)
                .wrapping_add(w[idx - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for idx in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[idx])
                .wrapping_add(w[idx]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0_u8; 32];
    for (idx, word) in h.iter().enumerate() {
        out[idx * 4..idx * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn assert_case(case: &VectorCase) {
    let kind = string_field(&case.construct, "type").expect("construct type");
    match kind.as_str() {
        "module_all" => {
            let names = string_array(&case.expected, "names").expect("names");
            let got = precondition_func_names();
            let from_all: Vec<String> = names
                .iter()
                .filter(|name| got.iter().any(|reg| reg == *name))
                .cloned()
                .collect();
            assert_eq!(got, from_all, "registry names for {}", case.id);
            assert_eq!(names.len(), 22, "{}", case.id);
            assert!(names.iter().any(|n| n == "check_preconditions"), "{}", case.id);
            assert!(
                names.iter().any(|n| n == "_find_component_indices"),
                "{}",
                case.id
            );
        }
        "precondition_func_names" => {
            let want = string_array(&case.expected, "names").expect("names");
            assert_eq!(precondition_func_names(), want, "{}", case.id);
        }
        "register_precondition" => {
            let name = string_field(&case.construct, "name").expect("name");
            let err = register_precondition(&name, |_| true).expect_err(&case.id);
            assert_eq!(
                string_field(&case.expected, "mode").expect("mode"),
                "value_error",
                "{}",
                case.id
            );
            let want = string_field(&case.expected, "message").expect("message");
            assert_eq!(err.to_string(), want, "{}", case.id);
        }
        "check_preconditions" => {
            let owned =
                OwnedContext::from_spec(object_field(&case.construct, "context").expect("context"));
            let ctx = owned.context();
            let names_json = array_field(&case.construct, "names").expect("names");
            let names: Vec<String> = names_json
                .iter()
                .map(|v| match v {
                    JsonValue::Str(s) => s.clone(),
                    _ => panic!("name must be string"),
                })
                .collect();
            let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
            let mode = string_field(&case.expected, "mode").expect("mode");
            if mode == "value_error" {
                let want = string_field(&case.expected, "message").expect("message");
                let err = check_preconditions(&name_refs, &ctx).expect_err(&case.id);
                assert_eq!(err.to_string(), want, "{}", case.id);
                return;
            }
            let result = check_preconditions(&name_refs, &ctx).unwrap_or_else(|err| {
                panic!("{} check_preconditions: {err}", case.id);
            });
            let ok = bool_field(&case.expected, "ok").expect("ok");
            assert_eq!(result.0, ok, "{}", case.id);
            match lookup(&case.expected, "failed") {
                Some(JsonValue::Null) | None => assert!(result.1.is_none(), "{}", case.id),
                Some(JsonValue::Str(name)) => {
                    assert_eq!(result.1.map(|s| s.to_string()), Some(name.clone()), "{}", case.id);
                }
                other => panic!("{} bad failed field: {other:?}", case.id),
            }
        }
        "_find_component_indices" => {
            let events = decode_events(&case.construct, "events");
            let seed = i64_field(&case.construct, "seed").expect("seed");
            let got = _find_component_indices(&events, seed).unwrap_or_else(|err| {
                panic!("{}: {err}", case.id);
            });
            let mut sorted = got;
            sorted.sort_unstable();
            let want = i64_set_from_expected(&case.expected).expect("sorted indices");
            assert_eq!(sorted, want, "{}", case.id);
        }
        "_find_torn_compaction_dropped_indices" => {
            let events = decode_events(&case.construct, "events");
            let boundary = i64_field(&case.construct, "boundary_index").expect("boundary_index");
            let got = _find_torn_compaction_dropped_indices(&events, boundary)
                .unwrap_or_else(|err| panic!("{}: {err}", case.id));
            let want = usize_set_from_expected(&case.expected).expect("sorted");
            assert_eq!(got, want, "{}", case.id);
        }
        "predicate" => assert_predicate(case),
        other => panic!("{}: unknown construct type {other}", case.id),
    }
}

fn assert_predicate(case: &VectorCase) {
    let name = string_field(&case.construct, "predicate").expect("predicate");
    let owned =
        OwnedContext::from_spec(object_field(&case.construct, "context").expect("context"));
    let ctx = owned.context();
    let mode = string_field(&case.expected, "mode").expect("mode");
    match mode.as_str() {
        "gap" => {
            let gap_id = string_field(&case.expected, "gap_id").expect("gap_id");
            let result = call_predicate(name.as_str(), &ctx);
            let err = result.expect_err(&case.id);
            assert_gap(&gap_id, &err, &case.id);
        }
        "bool" => {
            let want = bool_field(&case.expected, "value").expect("value");
            let got = call_predicate(name.as_str(), &ctx).expect(&case.id);
            assert_eq!(got, want, "{}", case.id);
        }
        other => panic!("{}: unsupported expected mode {other}", case.id),
    }
}

fn assert_gap(gap_id: &str, err: &PreconditionError, id: &str) {
    match gap_id {
        "GAP-preconditions-must-abstain" => {
            assert_eq!(err.to_string(), MUST_ABSTAIN_UNAVAILABLE, "{id}");
        }
        "GAP-preconditions-parent-candidates" => {
            assert_eq!(
                err.to_string(),
                FIND_QUALIFYING_PARENT_CANDIDATES_UNAVAILABLE,
                "{id}"
            );
        }
        "GAP-preconditions-canonical-json-bytes" => {
            assert!(
                err.to_string().contains("canonical_json_bytes"),
                "{id}: {err}"
            );
        }
        "GAP-preconditions-payload-content-hash" => {
            assert!(
                err.to_string().contains("payload_content_hash"),
                "{id}: {err}"
            );
        }
        other => panic!("{id}: unknown gap_id {other}"),
    }
}

fn call_predicate(name: &str, ctx: &PreconditionContext<'_>) -> Result<bool, PreconditionError> {
    match name {
        "no_sl203" => Ok(no_sl203(ctx)),
        "side_effects_known" => Ok(side_effects_known(ctx)),
        "repairability_is_safe_auto" => Ok(repairability_is_safe_auto(ctx)),
        "repairability_is_salvage" => Ok(repairability_is_salvage(ctx)),
        "source_hash_pinned" => Ok(source_hash_pinned(ctx)),
        "no_prior_safe_tool_after_cut" => no_prior_safe_tool_after_cut(ctx),
        "adjacent_identical_duplicate" => adjacent_identical_duplicate(ctx),
        "unique_parent_candidate" => unique_parent_candidate(ctx),
        "single_boundary_split" => single_boundary_split(ctx),
        "duplicate_projection_identical" => duplicate_projection_identical(ctx),
        "sl003_identical_duplicate" => Ok(sl003_identical_duplicate(ctx)),
        "salvage_policy" => Ok(salvage_policy(ctx)),
        "acknowledge_side_effects" => Ok(acknowledge_side_effects(ctx)),
        "branch_has_no_checkpoint" => branch_has_no_checkpoint(ctx),
        "sl108_present" => sl108_present(ctx),
        "torn_terminal_record" => Ok(torn_terminal_record(ctx)),
        other => panic!("unknown predicate {other}"),
    }
}

struct OwnedContext {
    findings: Vec<Finding>,
    events: Vec<EventValue>,
    profile: String,
    source_hash: String,
    policy: String,
    acknowledge: bool,
    finding_index: Option<usize>,
}

impl OwnedContext {
    fn from_spec(spec: &[(String, JsonValue)]) -> Self {
        let finding_index = i64_field(spec, "finding_index")
            .ok()
            .and_then(|idx| usize::try_from(idx).ok());
        Self {
            findings: decode_findings(spec, "findings"),
            events: decode_events(spec, "events"),
            profile: string_field(spec, "profile").unwrap_or_else(|_| "neutral".to_owned()),
            source_hash: string_field(spec, "source_hash").unwrap_or_default(),
            policy: string_field(spec, "policy").unwrap_or_else(|_| "conservative".to_owned()),
            acknowledge: bool_field(spec, "acknowledge_side_effects").unwrap_or(false),
            finding_index,
        }
    }

    fn context(&self) -> PreconditionContext<'_> {
        let mut ctx = PreconditionContext::new(
            &self.findings,
            &self.events,
            &self.profile,
            &self.source_hash,
        );
        ctx.policy = self.policy.as_str();
        ctx.acknowledge_side_effects = self.acknowledge;
        if let Some(idx) = self.finding_index {
            ctx.finding = self.findings.get(idx);
        }
        ctx
    }
}

fn decode_findings(spec: &[(String, JsonValue)], key: &str) -> Vec<Finding> {
    let Ok(items) = array_field(spec, key) else {
        return Vec::new();
    };
    items.iter().map(decode_finding).collect()
}

fn decode_finding(value: &JsonValue) -> Finding {
    let obj = as_object(value, "finding").unwrap();
    let code = string_field(obj, "code").expect("code");
    let severity = match string_field(obj, "severity").expect("severity").as_str() {
        "FATAL" => Severity::Fatal,
        "ERROR" => Severity::Error,
        "WARNING" => Severity::Warning,
        "INFO" => Severity::Info,
        other => panic!("unknown severity {other}"),
    };
    let repairability = match string_field(obj, "repairability")
        .expect("repairability")
        .as_str()
    {
        "DETERMINISTIC" => Repairability::Deterministic,
        "LOSSY_EXPLICIT" => Repairability::LossyExplicit,
        "MANUAL" => Repairability::Manual,
        "UNSUPPORTED" => Repairability::Unsupported,
        other => panic!("unknown repairability {other}"),
    };
    let message = string_field(obj, "message").expect("message");
    let src = object_field(obj, "source").expect("source");
    let path = string_field(src, "path").expect("path");
    let line = match lookup(src, "line") {
        None | Some(JsonValue::Null) => None,
        Some(JsonValue::Number(n)) => Some(SourceLine::Int(*n)),
        other => panic!("bad line: {other:?}"),
    };
    let record_id = optional_string_field(src, "record_id").ok().flatten();
    let source = SourceRef::try_new(&path, line, record_id.as_deref()).expect("source");
    let fingerprint = string_field(obj, "fingerprint").expect("fingerprint");
    let evidence = decode_evidence(obj);
    Finding::try_new(FindingInput {
        code: PyValue::string(code),
        severity: PyValue::severity(severity),
        repairability: PyValue::repairability(repairability),
        message: PyValue::string(message),
        source: PyValue::source(source),
        related_ids: PyValue::tuple(Vec::new()),
        fingerprint: PyValue::string(fingerprint),
        schema_version: PyValue::string(SCHEMA_VERSION),
        message_template: PyValue::None,
        evidence,
    })
    .expect("finding")
}

fn decode_evidence(obj: &[(String, JsonValue)]) -> PyValue {
    match lookup(obj, "evidence") {
        None | Some(JsonValue::Null) => PyValue::None,
        Some(JsonValue::Object(ev)) => {
            if let Some(pairs) = lookup(ev, "pairs") {
                let JsonValue::Array(items) = pairs else {
                    panic!("pairs must be array");
                };
                let mut entries = Vec::new();
                for pair in items {
                    let JsonValue::Array(two) = pair else {
                        panic!("pair must be array");
                    };
                    let JsonValue::Str(key) = &two[0] else {
                        panic!("key");
                    };
                    entries.push((PyValue::string(key.clone()), py_from_tagged(&two[1])));
                }
                PyValue::map(entries)
            } else {
                py_from_tagged(&JsonValue::Object(ev.to_vec()))
            }
        }
        other => panic!("evidence: {other:?}"),
    }
}

fn py_from_tagged(value: &JsonValue) -> PyValue {
    let obj = as_object(value, "tagged").unwrap();
    let tag = string_field(obj, "t").expect("t");
    match tag.as_str() {
        "null" => PyValue::None,
        "bool" => PyValue::bool_value(bool_field(obj, "v").expect("v")),
        "int" => PyValue::int(i64_field(obj, "v").expect("v")),
        "str" => PyValue::string(string_field(obj, "v").expect("v")),
        "list" => {
            let items = array_field(obj, "items").expect("items");
            PyValue::list(items.iter().map(py_from_tagged).collect())
        }
        "map" => {
            let entries = array_field(obj, "entries").expect("entries");
            let mut out = Vec::new();
            for pair in entries {
                let JsonValue::Array(two) = pair else {
                    panic!("entry");
                };
                let JsonValue::Str(key) = &two[0] else {
                    panic!("key");
                };
                out.push((PyValue::string(key.clone()), py_from_tagged(&two[1])));
            }
            PyValue::map(out)
        }
        other => panic!("bad tag {other}"),
    }
}

fn decode_events(spec: &[(String, JsonValue)], key: &str) -> Vec<EventValue> {
    let Ok(items) = array_field(spec, key) else {
        return Vec::new();
    };
    items
        .iter()
        .map(|item| {
            let wrapped = as_object(item, "event").expect("event");
            EventValue::Mapping(event_mapping_from_entries(wrapped))
        })
        .collect()
}

fn event_mapping_from_entries(obj: &[(String, JsonValue)]) -> EventMapping {
    let entries = array_field(obj, "entries").expect("entries");
    let mut out = Vec::new();
    for pair in entries {
        let JsonValue::Array(two) = pair else {
            panic!("pair");
        };
        let JsonValue::Str(key) = &two[0] else {
            panic!("key");
        };
        out.push((key.clone(), json_to_event_field(&two[1])));
    }
    EventMapping::new(out)
}

fn json_to_event_field(value: &JsonValue) -> EventField {
    let obj = as_object(value, "field").unwrap();
    let tag = string_field(obj, "t").expect("t");
    match tag.as_str() {
        "null" => EventField::Null,
        "bool" => EventField::Bool(bool_field(obj, "v").expect("v")),
        "int" => EventField::Int(i64_field(obj, "v").expect("v")),
        "str" => EventField::Str(string_field(obj, "v").expect("v")),
        "map" => {
            let nested = array_field(obj, "entries").expect("entries");
            let mut inner = Vec::new();
            for pair in nested {
                let JsonValue::Array(two) = pair else {
                    panic!("pair");
                };
                let JsonValue::Str(key) = &two[0] else {
                    panic!("key");
                };
                inner.push((key.clone(), json_to_event_field(&two[1])));
            }
            EventField::Mapping(EventMapping::new(inner))
        }
        other => panic!("unknown tag {other}"),
    }
}

fn i64_set_from_expected(expected: &[(String, JsonValue)]) -> Result<Vec<i64>, ParseError> {
    let items = array_field(expected, "sorted")?;
    items
        .iter()
        .map(|v| match v {
            JsonValue::Number(n) => Ok(*n),
            _ => Err(ParseError {
                message: "index must be number".into(),
            }),
        })
        .collect()
}

fn usize_set_from_expected(expected: &[(String, JsonValue)]) -> Result<BTreeSet<usize>, ParseError> {
    let items = array_field(expected, "sorted")?;
    let mut out = BTreeSet::new();
    for v in items {
        let JsonValue::Number(n) = v else {
            return Err(ParseError {
                message: "index must be number".into(),
            });
        };
        let index = usize::try_from(*n).map_err(|_| ParseError {
            message: "bad usize".into(),
        })?;
        out.insert(index);
    }
    Ok(out)
}

fn string_array(obj: &[(String, JsonValue)], key: &str) -> Result<Vec<String>, ParseError> {
    let items = array_field(obj, key)?;
    items
        .iter()
        .map(|v| match v {
            JsonValue::Str(s) => Ok(s.clone()),
            _ => Err(ParseError {
                message: format!("{key} items must be strings"),
            }),
        })
        .collect()
}

fn bool_field(obj: &[(String, JsonValue)], key: &str) -> Result<bool, ParseError> {
    match lookup(obj, key) {
        Some(JsonValue::Bool(b)) => Ok(*b),
        _ => Err(ParseError {
            message: format!("{key} must be bool"),
        }),
    }
}

fn i64_field(obj: &[(String, JsonValue)], key: &str) -> Result<i64, ParseError> {
    match lookup(obj, key) {
        Some(JsonValue::Number(n)) => Ok(*n),
        _ => Err(ParseError {
            message: format!("{key} must be number"),
        }),
    }
}

fn optional_string_field(obj: &[(String, JsonValue)], key: &str) -> Result<Option<String>, ParseError> {
    match lookup(obj, key) {
        None | Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::Str(s)) => Ok(Some(s.clone())),
        _ => Err(ParseError {
            message: format!("{key} must be string or null"),
        }),
    }
}

fn lookup<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

// --- minimal JSON (vectors.json only) ---

#[derive(Debug, Clone, PartialEq)]
enum JsonValue {
    Null,
    Bool(bool),
    Str(String),
    Number(i64),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

#[derive(Debug)]
struct ParseError {
    message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

fn parse_document(input: &str) -> Result<Vec<VectorCase>, ParseError> {
    let (value, rest) = parse_value(input.trim_start())?;
    if !rest.trim().is_empty() {
        return Err(ParseError {
            message: "trailing JSON".into(),
        });
    }
    let JsonValue::Object(root) = value else {
        return Err(ParseError {
            message: "root must be object".into(),
        });
    };
    let vectors = root
        .iter()
        .find(|(k, _)| k == "vectors")
        .ok_or_else(|| ParseError {
            message: "missing vectors".into(),
        })?;
    let JsonValue::Array(items) = &vectors.1 else {
        return Err(ParseError {
            message: "vectors must be array".into(),
        });
    };
    items.iter().map(parse_vector_case).collect()
}

fn parse_vector_case(value: &JsonValue) -> Result<VectorCase, ParseError> {
    let obj = as_object(value, "vector")?;
    let id = string_field(obj, "id")?;
    let construct = object_field(obj, "construct")?.to_vec();
    let expected = object_field(obj, "expected")?.to_vec();
    Ok(VectorCase {
        id,
        construct,
        expected,
    })
}

fn as_object<'a>(value: &'a JsonValue, ctx: &str) -> Result<&'a [(String, JsonValue)], ParseError> {
    match value {
        JsonValue::Object(obj) => Ok(obj),
        _ => Err(ParseError {
            message: format!("{ctx} must be object"),
        }),
    }
}

fn object_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [(String, JsonValue)], ParseError> {
    let value = obj
        .iter()
        .find(|(k, _)| k == key)
        .ok_or_else(|| ParseError {
            message: format!("missing key {key}"),
        })?;
    as_object(&value.1, key)
}

fn array_field<'a>(
    obj: &'a [(String, JsonValue)],
    key: &str,
) -> Result<&'a [JsonValue], ParseError> {
    let value = obj
        .iter()
        .find(|(k, _)| k == key)
        .ok_or_else(|| ParseError {
            message: format!("missing key {key}"),
        })?;
    match &value.1 {
        JsonValue::Array(items) => Ok(items.as_slice()),
        _ => Err(ParseError {
            message: format!("{key} must be array"),
        }),
    }
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, ParseError> {
    match obj.iter().find(|(k, _)| k == key) {
        Some((_, JsonValue::Str(s))) => Ok(s.clone()),
        _ => Err(ParseError {
            message: format!("{key} must be string"),
        }),
    }
}

fn parse_value(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let input = input.trim_start();
    if input.is_empty() {
        return Err(ParseError {
            message: "unexpected end".into(),
        });
    }
    match input.as_bytes()[0] {
        b'n' => parse_literal(input, "null", JsonValue::Null),
        b't' => parse_literal(input, "true", JsonValue::Bool(true)),
        b'f' => parse_literal(input, "false", JsonValue::Bool(false)),
        b'"' => parse_string(input).map(|(s, rest)| (JsonValue::Str(s), rest)),
        b'[' => parse_array(input),
        b'{' => parse_object(input),
        b'0'..=b'9' | b'-' => parse_number(input),
        _ => Err(ParseError {
            message: "invalid JSON value".into(),
        }),
    }
}

fn parse_literal<'a>(
    input: &'a str,
    word: &str,
    value: JsonValue,
) -> Result<(JsonValue, &'a str), ParseError> {
    if let Some(rest) = input.strip_prefix(word) {
        Ok((value, rest))
    } else {
        Err(ParseError {
            message: format!("expected {word}"),
        })
    }
}

fn parse_number(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut end = 0usize;
    let bytes = input.as_bytes();
    let mut index = 0usize;
    if bytes[0] == b'-' {
        index = 1;
        end = 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end <= index {
        return Err(ParseError {
            message: "invalid number".into(),
        });
    }
    let num = input[..end]
        .parse::<i64>()
        .map_err(|_| ParseError {
            message: "invalid int".into(),
        })?;
    Ok((JsonValue::Number(num), &input[end..]))
}

fn parse_array(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
    if let Some(tail) = rest.strip_prefix(']') {
        return Ok((JsonValue::Array(items), tail));
    }
    loop {
        let (item, tail) = parse_value(rest)?;
        items.push(item);
        rest = tail.trim_start();
        if let Some(tail) = rest.strip_prefix(']') {
            return Ok((JsonValue::Array(items), tail));
        }
        if !rest.starts_with(',') {
            return Err(ParseError {
                message: "expected , or ] in array".into(),
            });
        }
        rest = rest[1..].trim_start();
    }
}

fn parse_object(input: &str) -> Result<(JsonValue, &str), ParseError> {
    let mut rest = &input[1..];
    let mut items = Vec::new();
    rest = rest.trim_start();
    if let Some(tail) = rest.strip_prefix('}') {
        return Ok((JsonValue::Object(items), tail));
    }
    loop {
        let (key, tail) = parse_string(rest)?;
        rest = tail.trim_start();
        if !rest.starts_with(':') {
            return Err(ParseError {
                message: "expected : in object".into(),
            });
        }
        rest = rest[1..].trim_start();
        let (value, tail) = parse_value(rest)?;
        items.push((key, value));
        rest = tail.trim_start();
        if let Some(tail) = rest.strip_prefix('}') {
            return Ok((JsonValue::Object(items), tail));
        }
        if !rest.starts_with(',') {
            return Err(ParseError {
                message: "expected , or } in object".into(),
            });
        }
        rest = rest[1..].trim_start();
    }
}

fn parse_string(input: &str) -> Result<(String, &str), ParseError> {
    if !input.starts_with('"') {
        return Err(ParseError {
            message: "expected string".into(),
        });
    }
    let mut out = String::new();
    let mut chars = input[1..].char_indices();
    loop {
        let (idx, ch) = chars.next().ok_or_else(|| ParseError {
            message: "unterminated string".into(),
        })?;
        match ch {
            '"' => {
                let rest_idx = idx + 1;
                return Ok((out, &input[rest_idx + 1..]));
            }
            '\\' => {
                let (_, esc) = chars.next().ok_or_else(|| ParseError {
                    message: "bad escape".into(),
                })?;
                match esc {
                    '"' | '\\' | '/' => out.push(esc),
                    'b' => out.push('\u{8}'),
                    'f' => out.push('\u{c}'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        let hex: String = chars.by_ref().take(4).map(|(_, c)| c).collect();
                        let code = u32::from_str_radix(&hex, 16).map_err(|_| ParseError {
                            message: "bad \\u".into(),
                        })?;
                        let decoded = char::from_u32(code).ok_or_else(|| ParseError {
                            message: "bad unicode".into(),
                        })?;
                        out.push(decoded);
                    }
                    _ => {
                        return Err(ParseError {
                            message: "unsupported escape".into(),
                        });
                    }
                }
            }
            _ => out.push(ch),
        }
    }
}
