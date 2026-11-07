//! Public registry and minimum spans for `model::secret_families`.
//!
//! Offsets are the same pinned `re.search` results locked by the unit tests.

use model::secret_families::{
    search_anthropic_api_key, search_aws_access_key, search_bearer_token,
    search_generic_credential_assignment, search_github_oauth_token, search_github_pat_classic,
    search_github_pat_fine_grained, search_gitlab_pat, search_google_api_key,
    search_huggingface_token, search_jwt, search_npm_token, search_openai_api_key,
    search_openrouter_api_key, search_private_key_block, search_slack_token, search_stripe_key,
    search_stripe_webhook_secret, search_supabase_pat, search_telegram_bot_token, FAMILY_LITERALS,
    SECRET_FAMILIES,
};

fn lit(name: &str, index: usize) -> &'static [u8] {
    for (key, values) in FAMILY_LITERALS {
        if *key == name {
            return values[index];
        }
    }
    panic!("missing literal {name}");
}

fn assembled(lead: &[u8], prefix: &[u8], body_len: usize, fill: u8, tail: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(lead.len() + prefix.len() + body_len + tail.len());
    out.extend_from_slice(lead);
    out.extend_from_slice(prefix);
    out.extend(std::iter::repeat_n(fill, body_len));
    out.extend_from_slice(tail);
    out
}

#[test]
fn public_registry_matches_pinned_order() {
    assert_eq!(SECRET_FAMILIES.len(), 20);
    assert_eq!(FAMILY_LITERALS.len(), 18);
    assert_eq!(SECRET_FAMILIES[0].name, "anthropic-api-key");
    assert_eq!(SECRET_FAMILIES[0].group, 0);
    assert_eq!(SECRET_FAMILIES[19].name, "generic-credential-assignment");
    assert_eq!(SECRET_FAMILIES[19].group, 1);
    assert_eq!(FAMILY_LITERALS[0].0, "anthropic-api-key");
    assert_eq!(FAMILY_LITERALS[17].0, "private-key-block");
    assert_eq!(FAMILY_LITERALS[17].1[0], b"PRIVATE KEY-----");
    assert!(
        FAMILY_LITERALS
            .iter()
            .all(|(name, _)| *name != "telegram-bot-token"
                && *name != "generic-credential-assignment")
    );
    let names: Vec<&str> = SECRET_FAMILIES.iter().map(|family| family.name).collect();
    assert_eq!(
        names,
        [
            "anthropic-api-key",
            "openai-api-key",
            "openrouter-api-key",
            "github-pat-classic",
            "github-pat-fine-grained",
            "github-oauth-token",
            "stripe-webhook-secret",
            "stripe-key",
            "aws-access-key",
            "google-api-key",
            "slack-token",
            "gitlab-pat",
            "bearer-token",
            "npm-token",
            "huggingface-token",
            "supabase-pat",
            "telegram-bot-token",
            "jwt",
            "private-key-block",
            "generic-credential-assignment",
        ]
    );
}

#[test]
fn public_table_search_matches_named_functions() {
    let sample = assembled(b"..", lit("anthropic-api-key", 0), 20, b'a', b"");
    assert_eq!(
        (SECRET_FAMILIES[0].search)(&sample),
        search_anthropic_api_key(&sample)
    );
    assert_eq!((SECRET_FAMILIES[0].search)(&sample), Some((2, 29)));

    let stripe = assembled(b" ", lit("stripe-key", 0), 16, b'a', b"");
    assert_eq!(
        (SECRET_FAMILIES[7].search)(&stripe),
        search_stripe_key(&stripe)
    );
    assert_eq!((SECRET_FAMILIES[7].search)(&stripe), Some((1, 25)));

    let mut generic = b"password=".to_vec();
    generic.extend(std::iter::repeat_n(b'a', 8));
    assert_eq!(
        (SECRET_FAMILIES[19].search)(&generic),
        search_generic_credential_assignment(&generic)
    );
    assert_eq!((SECRET_FAMILIES[19].search)(&generic), Some((9, 17)));
}

#[test]
fn public_minimum_spans_match_pinned_re_search() {
    assert_eq!(
        search_openai_api_key(&assembled(b"", lit("openai-api-key", 0), 20, b'a', b"")),
        Some((0, 23))
    );
    assert_eq!(
        search_openrouter_api_key(&assembled(b"", lit("openrouter-api-key", 0), 48, b'a', b"")),
        Some((0, 57))
    );
    assert_eq!(
        search_github_pat_classic(&assembled(b"", lit("github-pat-classic", 0), 36, b'a', b"")),
        Some((0, 40))
    );
    assert_eq!(
        search_github_pat_fine_grained(&assembled(
            b"",
            lit("github-pat-fine-grained", 0),
            22,
            b'a',
            b""
        )),
        Some((0, 33))
    );
    assert_eq!(
        search_github_oauth_token(&assembled(b"", lit("github-oauth-token", 0), 36, b'a', b"")),
        Some((0, 40))
    );
    assert_eq!(
        search_stripe_webhook_secret(&assembled(
            b"",
            lit("stripe-webhook-secret", 0),
            24,
            b'a',
            b""
        )),
        Some((0, 30))
    );
    assert_eq!(
        search_aws_access_key(&assembled(b"", lit("aws-access-key", 0), 16, b'0', b"")),
        Some((0, 20))
    );
    assert_eq!(
        search_google_api_key(&assembled(b"", lit("google-api-key", 0), 20, b'a', b"")),
        Some((0, 24))
    );
    let mut slack = lit("slack-token", 0).to_vec();
    slack.push(b'b');
    slack.push(b'-');
    slack.extend(std::iter::repeat_n(b'a', 16));
    assert_eq!(search_slack_token(&slack), Some((0, 21)));
    assert_eq!(
        search_gitlab_pat(&assembled(b"", lit("gitlab-pat", 0), 20, b'a', b"")),
        Some((0, 26))
    );
    let mut bearer = lit("bearer-token", 0).to_vec();
    bearer.push(b' ');
    bearer.extend(std::iter::repeat_n(b'a', 16));
    assert_eq!(search_bearer_token(&bearer), Some((0, 23)));
    assert_eq!(
        search_npm_token(&assembled(b"", lit("npm-token", 0), 20, b'a', b"")),
        Some((0, 24))
    );
    assert_eq!(
        search_huggingface_token(&assembled(b"", lit("huggingface-token", 0), 20, b'a', b"")),
        Some((0, 23))
    );
    assert_eq!(
        search_supabase_pat(&assembled(b"", lit("supabase-pat", 0), 40, b'a', b"")),
        Some((0, 44))
    );
    let mut telegram = b"12345678:".to_vec();
    telegram.extend(std::iter::repeat_n(b'a', 35));
    assert_eq!(search_telegram_bot_token(&telegram), Some((0, 44)));
    let mut jwt = lit("jwt", 0).to_vec();
    jwt.extend(std::iter::repeat_n(b'a', 10));
    jwt.push(b'.');
    jwt.extend(std::iter::repeat_n(b'b', 10));
    jwt.push(b'.');
    jwt.extend(std::iter::repeat_n(b'c', 10));
    assert_eq!(search_jwt(&jwt), Some((0, 35)));
    let mut pem = b"-----BEGIN ".to_vec();
    pem.extend_from_slice(lit("private-key-block", 0));
    assert_eq!(search_private_key_block(&pem), Some((0, 27)));
}
