//! Bounded batch probe for RX-P1.6. Calls actual ported crate implementations.
#![forbid(unsafe_code)]

use std::io::{self, BufRead, Read, Write};

use adapters::safe_value::{safe_discriminator, safe_type_value, PyValue};
use codec::canonical_codec::{CanonicalCodec, ObjectKey, PurePythonCanonicalCodec, Value};
use serde_json::{json, Value as Json};

const MAX_LINE: usize = 262_144;
const MAX_CASES: u64 = 100_000;

type ProbeResult<T> = Result<T, &'static str>;

fn text<'a>(value: &'a Json, key: &str) -> ProbeResult<&'a str> {
    value.get(key).and_then(Json::as_str).ok_or("invalid_input")
}

fn bytes_hex(text: &str) -> ProbeResult<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return Err("invalid_hex");
    }
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|_| "invalid_hex")?;
            u8::from_str_radix(pair, 16).map_err(|_| "invalid_hex")
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 15)]));
    }
    out
}

fn codec_value(node: &Json, depth: usize) -> ProbeResult<Value> {
    if depth > 24 {
        return Err("input_depth");
    }
    match text(node, "kind")? {
        "null" => Ok(Value::Null),
        "bool" => Ok(Value::bool(node["value"].as_bool().ok_or("invalid_bool")?)),
        "str" => Ok(Value::string(text(node, "value")?)),
        "int" => Ok(Value::int_i128(
            text(node, "value")?.parse().map_err(|_| "invalid_int")?,
        )),
        "float" => {
            let bits = u64::from_str_radix(text(node, "bits")?, 16).map_err(|_| "invalid_float")?;
            Ok(Value::float(f64::from_bits(bits)))
        }
        "array" => {
            let values = node["items"].as_array().ok_or("invalid_array")?;
            values
                .iter()
                .map(|value| codec_value(value, depth + 1))
                .collect::<ProbeResult<Vec<_>>>()
                .map(Value::array)
        }
        "object" => {
            let entries = node["items"].as_array().ok_or("invalid_object")?;
            let mut values = Vec::new();
            for entry in entries {
                let pair = entry
                    .as_array()
                    .filter(|p| p.len() == 2)
                    .ok_or("invalid_pair")?;
                let key = pair[0].as_str().ok_or("invalid_key")?;
                values.push((ObjectKey::string(key), codec_value(&pair[1], depth + 1)?));
            }
            Ok(Value::object(values))
        }
        "foreign" => Ok(Value::foreign("object")),
        "bad_key" => Ok(Value::object(vec![(
            ObjectKey::non_string("42"),
            Value::Null,
        )])),
        "cycle_array" => {
            let (value, items) = Value::array_cell(Vec::new());
            items.borrow_mut().push(value.clone());
            Ok(value)
        }
        "cycle_object" => {
            let (value, items) = Value::object_cell(Vec::new());
            items
                .borrow_mut()
                .push((ObjectKey::string("self"), value.clone()));
            Ok(value)
        }
        _ => Err("unknown_kind"),
    }
}

fn adapter_value(node: &Json) -> ProbeResult<PyValue<'_>> {
    let kind = text(node, "kind")?;
    let length = || -> ProbeResult<usize> {
        let n = node["length"]
            .as_u64()
            .filter(|n| *n <= 512)
            .ok_or("invalid_length")?;
        usize::try_from(n).map_err(|_| "invalid_length")
    };
    match kind {
        "str" => Ok(PyValue::Str(text(node, "value")?)),
        "int" => Ok(PyValue::Int),
        "float" => Ok(PyValue::Float),
        "bool" => Ok(PyValue::Bool),
        "null" => Ok(PyValue::None),
        "bytes" => Ok(PyValue::Bytes(length()?)),
        "array" => Ok(PyValue::List(length()?)),
        "object" => Ok(PyValue::Dict(length()?)),
        "tuple" => Ok(PyValue::Tuple(length()?)),
        "set" => Ok(PyValue::Set(length()?)),
        "foreign" => Ok(PyValue::Other("object")),
        _ => Err("unknown_kind"),
    }
}

fn evaluate(case: &Json, expected_id: u64) -> ProbeResult<Json> {
    let id = case["id"].as_u64().ok_or("invalid_id")?;
    if id != expected_id {
        return Err("case_order");
    }
    let input = &case["input"];
    match text(case, "op")? {
        "codec" => {
            let value = codec_value(input, 0)?;
            let newline = case["newline"].as_bool().ok_or("invalid_newline")?;
            match PurePythonCanonicalCodec.canonical_json_bytes(&value, newline) {
                Ok(bytes) => Ok(json!({"id":id,"ok":true,"output_hex":hex(&bytes)})),
                Err(error) => Ok(json!({"id":id,"ok":false,"error":error.to_string()})),
            }
        }
        "adapter_discriminator" => {
            let (value, truncated) = safe_discriminator(adapter_value(input)?);
            Ok(json!({"id":id,"ok":true,"output":[value,truncated]}))
        }
        "adapter_type" => {
            Ok(json!({"id":id,"ok":true,"output":safe_type_value(adapter_value(input)?)}))
        }
        "adapter_detect" => {
            let data = bytes_hex(text(input, "hex")?)?;
            let score = adapters::canonical::detect_canonical(&data, "synthetic.jsonl");
            Ok(json!({"id":id,"ok":true,"output":format!("{:016x}",score.to_bits())}))
        }
        _ => Err("unknown_operation"),
    }
}

fn run() -> ProbeResult<()> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let mut id = 0_u64;
    loop {
        let mut line = Vec::new();
        let read = Read::by_ref(&mut reader)
            .take((MAX_LINE + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|_| "read_failed")?;
        if read == 0 {
            break;
        }
        if read > MAX_LINE || id >= MAX_CASES {
            return Err("input_budget");
        }
        let case: Json = serde_json::from_slice(&line).map_err(|_| "invalid_json")?;
        let response = evaluate(&case, id)?;
        serde_json::to_writer(&mut out, &response).map_err(|_| "write_failed")?;
        out.write_all(b"\n").map_err(|_| "write_failed")?;
        id += 1;
    }
    out.flush().map_err(|_| "write_failed")
}

fn main() {
    if let Err(reason) = run() {
        eprintln!("reason={reason}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_calls_real_implementation_and_preserves_refusals() {
        let case = json!({"id":0,"op":"codec","newline":true,"input":{"kind":"int","value":"42"}});
        assert_eq!(
            evaluate(&case, 0),
            Ok(json!({"id":0,"ok":true,"output_hex":"34320a"}))
        );
        for kind in ["foreign", "bad_key", "cycle_array", "cycle_object"] {
            let case = json!({"id":0,"op":"codec","newline":false,"input":{"kind":kind}});
            let response = evaluate(&case, 0).unwrap();
            assert_eq!(response["ok"], false);
            assert!(response["error"]
                .as_str()
                .is_some_and(|error| !error.is_empty()));
        }
    }

    #[test]
    fn malformed_inputs_fail_infrastructure_not_a_model_refusal() {
        assert_eq!(
            evaluate(&json!({"id":1,"op":"codec"}), 0),
            Err("case_order")
        );
        assert_eq!(
            evaluate(&json!({"id":0,"op":"unknown"}), 0),
            Err("unknown_operation")
        );
        assert_eq!(bytes_hex("zz"), Err("invalid_hex"));
        assert_eq!(bytes_hex("a"), Err("invalid_hex"));
        assert_eq!(bytes_hex("á"), Err("invalid_hex"));
        let invalid = json!({"id":0,"op":"codec","newline":false,"input":{"kind":"int","value":"not-an-int"}});
        assert_eq!(evaluate(&invalid, 0), Err("invalid_int"));
    }

    #[test]
    fn adapter_detect_reports_exact_float_bits() {
        let case = json!({"id":0,"op":"adapter_detect","input":{"hex":""}});
        let expected = adapters::canonical::detect_canonical(b"", "synthetic.jsonl");
        assert_eq!(
            evaluate(&case, 0).unwrap()["output"],
            format!("{:016x}", expected.to_bits())
        );
    }
}
