//! Pinned argparse declaration parity; no stdio/runtime success claim.
use cli::mcp::configure;
use report::report::short_hash;
use serde_json::{json, Value};
use std::path::Path;

#[test]
fn actual_python_configure_vector_matches_bytes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../parity/vectors/cli.mcp");
    let raw = std::fs::read_to_string(root.join("vectors.json")).unwrap();
    let vectors: Value = serde_json::from_str(&raw).unwrap();
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
    let provenance: Value =
        serde_json::from_slice(&std::fs::read(root.join("PROVENANCE.json")).unwrap()).unwrap();
    let coverage: Value =
        serde_json::from_slice(&std::fs::read(root.join("coverage.json")).unwrap()).unwrap();
    let hash = "a679169b90a5b0b2ecb5c79e0020bb28f75673d72c4a78b6a26723ee0727a88c";
    assert_eq!(short_hash(&raw, 64), hash);
    assert_eq!(manifest["vectors_sha256"], hash);
    assert_eq!(
        manifest["python_commit"],
        "02694d537104659df66cdd084354739f3cccc440"
    );
    assert_eq!(vectors["python_commit"], manifest["python_commit"]);
    assert_eq!(provenance["contains_real_data"], false);
    assert_eq!(coverage["rows"], json!([]));
    let source =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/mcp.rs")).unwrap();
    assert_eq!(manifest["rust_sha256"], short_hash(&source, 64));
    let cases = vectors["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 1);
    assert_eq!(manifest["vector_count"], 1);
    for case in cases {
        assert_eq!(case["id"], "configure");
        let spec = configure();
        let actual = json!({"name":spec.name,"help":spec.help,"description":spec.description});
        assert_eq!(
            serde_json::to_string(&actual).unwrap().as_bytes(),
            case["expected_json"].as_str().unwrap().as_bytes()
        );
    }
}
