//! Secret-shape registry shared by detection and adapter minimization (B14).
//!
//! Port of `src/sesslint/secret_families.py` lines 1–156
//! @ `e91d50b2ecea57ef4dd900e3b0b87b14946e847e`.
//!
//! [`SECRET_FAMILIES`] keeps the pinned order. [`SecretFamily::group`] is the
//! Python group index: `0` is the whole match and `1` is the first capture.
//! [`SecretFamily::search`] returns that group's span as `(start, end)` with
//! `end` exclusive, matching `re.Match.span`. The search is the leftmost match.
//! When the selected group did not participate, the result is [`None`].
//!
//! Every family except `generic-credential-assignment` may start only when the
//! previous byte is absent or outside ASCII letters, digits, `_`, and `-`.
//! [`FAMILY_LITERALS`] keeps Python insertion order and omits
//! `telegram-bot-token` and `generic-credential-assignment`.
//!
//! Matchers walk the bytes directly. There is no `regex` dependency.

/// Python group 0: the whole match.
const WHOLE_MATCH: usize = 0;
/// Python group 1: the first capturing group.
const FIRST_CAPTURE: usize = 1;

const ANTHROPIC_PREFIX: &[u8] = b"sk-ant-";
const OPENAI_PREFIX: &[u8] = b"sk-";
const OPENROUTER_PREFIX: &[u8] = b"sk-or-v1-";
const GITHUB_CLASSIC_PREFIX: &[u8] = b"ghp_";
const GITHUB_FINE_PREFIX: &[u8] = b"github_pat_";
const GITHUB_OAUTH_GHO: &[u8] = b"gho_";
const GITHUB_OAUTH_GHS: &[u8] = b"ghs_";
const GITHUB_OAUTH_GHR: &[u8] = b"ghr_";
const GITHUB_OAUTH_GHU: &[u8] = b"ghu_";
const STRIPE_WEBHOOK_PREFIX: &[u8] = b"whsec_";
const STRIPE_SK_LIVE: &[u8] = b"sk_live_";
const STRIPE_SK_TEST: &[u8] = b"sk_test_";
const STRIPE_RK_LIVE: &[u8] = b"rk_live_";
const STRIPE_RK_TEST: &[u8] = b"rk_test_";
const AWS_AKIA: &[u8] = b"AKIA";
const AWS_ASIA: &[u8] = b"ASIA";
const GOOGLE_PREFIX: &[u8] = b"AIza";
const SLACK_PREFIX: &[u8] = b"xox";
const GITLAB_PREFIX: &[u8] = b"glpat-";
const BEARER_WORD: &[u8] = b"bearer";
const NPM_PREFIX: &[u8] = b"npm_";
const HUGGINGFACE_PREFIX: &[u8] = b"hf_";
const SUPABASE_PREFIX: &[u8] = b"sbp_";
const JWT_PREFIX: &[u8] = b"eyJ";
const PEM_BEGIN: &[u8] = b"-----BEGIN ";
const PEM_END: &[u8] = b"PRIVATE KEY-----";

/// One entry of [`SECRET_FAMILIES`], in the pinned Python tuple order.
#[derive(Clone, Copy, Debug)]
pub struct SecretFamily {
    /// Family id.
    pub name: &'static str,
    /// Leftmost search. The span is `span(group)` for [`Self::group`].
    pub search: fn(&[u8]) -> Option<(usize, usize)>,
    /// Capture group reported by [`Self::search`].
    pub group: usize,
}

/// Pinned `SECRET_FAMILIES` order. The third field is the group index.
pub const SECRET_FAMILIES: &[SecretFamily] = &[
    SecretFamily {
        name: "anthropic-api-key",
        search: search_anthropic_api_key,
        group: WHOLE_MATCH,
    },
    SecretFamily {
        name: "openai-api-key",
        search: search_openai_api_key,
        group: WHOLE_MATCH,
    },
    SecretFamily {
        name: "openrouter-api-key",
        search: search_openrouter_api_key,
        group: WHOLE_MATCH,
    },
    SecretFamily {
        name: "github-pat-classic",
        search: search_github_pat_classic,
        group: WHOLE_MATCH,
    },
    SecretFamily {
        name: "github-pat-fine-grained",
        search: search_github_pat_fine_grained,
        group: WHOLE_MATCH,
    },
    SecretFamily {
        name: "github-oauth-token",
        search: search_github_oauth_token,
        group: WHOLE_MATCH,
    },
    SecretFamily {
        name: "stripe-webhook-secret",
        search: search_stripe_webhook_secret,
        group: WHOLE_MATCH,
    },
    SecretFamily {
        name: "stripe-key",
        search: search_stripe_key,
        group: WHOLE_MATCH,
    },
    SecretFamily {
        name: "aws-access-key",
        search: search_aws_access_key,
        group: WHOLE_MATCH,
    },
    SecretFamily {
        name: "google-api-key",
        search: search_google_api_key,
        group: WHOLE_MATCH,
    },
    SecretFamily {
        name: "slack-token",
        search: search_slack_token,
        group: WHOLE_MATCH,
    },
    SecretFamily {
        name: "gitlab-pat",
        search: search_gitlab_pat,
        group: WHOLE_MATCH,
    },
    SecretFamily {
        name: "bearer-token",
        search: search_bearer_token,
        group: WHOLE_MATCH,
    },
    SecretFamily {
        name: "npm-token",
        search: search_npm_token,
        group: WHOLE_MATCH,
    },
    SecretFamily {
        name: "huggingface-token",
        search: search_huggingface_token,
        group: WHOLE_MATCH,
    },
    SecretFamily {
        name: "supabase-pat",
        search: search_supabase_pat,
        group: WHOLE_MATCH,
    },
    SecretFamily {
        name: "telegram-bot-token",
        search: search_telegram_bot_token,
        group: WHOLE_MATCH,
    },
    SecretFamily {
        name: "jwt",
        search: search_jwt,
        group: WHOLE_MATCH,
    },
    SecretFamily {
        name: "private-key-block",
        search: search_private_key_block,
        group: WHOLE_MATCH,
    },
    SecretFamily {
        name: "generic-credential-assignment",
        search: search_generic_credential_assignment,
        group: FIRST_CAPTURE,
    },
];

/// Pinned `FAMILY_LITERALS` insertion order.
///
/// `telegram-bot-token` and `generic-credential-assignment` are absent.
pub const FAMILY_LITERALS: &[(&str, &[&[u8]])] = &[
    ("anthropic-api-key", &[ANTHROPIC_PREFIX]),
    ("openai-api-key", &[OPENAI_PREFIX]),
    ("openrouter-api-key", &[OPENROUTER_PREFIX]),
    ("github-pat-classic", &[GITHUB_CLASSIC_PREFIX]),
    ("github-pat-fine-grained", &[GITHUB_FINE_PREFIX]),
    (
        "github-oauth-token",
        &[
            GITHUB_OAUTH_GHO,
            GITHUB_OAUTH_GHS,
            GITHUB_OAUTH_GHR,
            GITHUB_OAUTH_GHU,
        ],
    ),
    ("stripe-webhook-secret", &[STRIPE_WEBHOOK_PREFIX]),
    (
        "stripe-key",
        &[
            STRIPE_SK_LIVE,
            STRIPE_SK_TEST,
            STRIPE_RK_LIVE,
            STRIPE_RK_TEST,
        ],
    ),
    ("aws-access-key", &[AWS_AKIA, AWS_ASIA]),
    ("google-api-key", &[GOOGLE_PREFIX]),
    ("slack-token", &[SLACK_PREFIX]),
    ("gitlab-pat", &[GITLAB_PREFIX]),
    ("bearer-token", &[BEARER_WORD]),
    ("npm-token", &[NPM_PREFIX]),
    ("huggingface-token", &[HUGGINGFACE_PREFIX]),
    ("supabase-pat", &[SUPABASE_PREFIX]),
    ("jwt", &[JWT_PREFIX]),
    ("private-key-block", &[PEM_END]),
];

/// Search for the leftmost `anthropic-api-key` span.
pub fn search_anthropic_api_key(haystack: &[u8]) -> Option<(usize, usize)> {
    search_prefixes(haystack, &[ANTHROPIC_PREFIX], 20, is_ascii_alnum_us_hyphen)
}

/// Search for the leftmost `openai-api-key` span.
pub fn search_openai_api_key(haystack: &[u8]) -> Option<(usize, usize)> {
    search_prefixes(haystack, &[OPENAI_PREFIX], 20, is_ascii_alnum)
}

/// Search for the leftmost `openrouter-api-key` span.
pub fn search_openrouter_api_key(haystack: &[u8]) -> Option<(usize, usize)> {
    search_prefixes(haystack, &[OPENROUTER_PREFIX], 48, is_lower_hex)
}

/// Search for the leftmost `github-pat-classic` span.
pub fn search_github_pat_classic(haystack: &[u8]) -> Option<(usize, usize)> {
    search_prefixes(haystack, &[GITHUB_CLASSIC_PREFIX], 36, is_ascii_alnum)
}

/// Search for the leftmost `github-pat-fine-grained` span.
pub fn search_github_pat_fine_grained(haystack: &[u8]) -> Option<(usize, usize)> {
    search_prefixes(haystack, &[GITHUB_FINE_PREFIX], 22, is_ascii_word_byte)
}

/// Search for the leftmost `github-oauth-token` span.
pub fn search_github_oauth_token(haystack: &[u8]) -> Option<(usize, usize)> {
    search_prefixes(
        haystack,
        &[
            GITHUB_OAUTH_GHO,
            GITHUB_OAUTH_GHS,
            GITHUB_OAUTH_GHR,
            GITHUB_OAUTH_GHU,
        ],
        36,
        is_ascii_alnum,
    )
}

/// Search for the leftmost `stripe-webhook-secret` span.
pub fn search_stripe_webhook_secret(haystack: &[u8]) -> Option<(usize, usize)> {
    search_prefixes(haystack, &[STRIPE_WEBHOOK_PREFIX], 24, is_ascii_alnum)
}

/// Search for the leftmost `stripe-key` span.
pub fn search_stripe_key(haystack: &[u8]) -> Option<(usize, usize)> {
    search_prefixes(
        haystack,
        &[
            STRIPE_SK_LIVE,
            STRIPE_SK_TEST,
            STRIPE_RK_LIVE,
            STRIPE_RK_TEST,
        ],
        16,
        is_ascii_alnum,
    )
}

/// Search for the leftmost `aws-access-key` span.
pub fn search_aws_access_key(haystack: &[u8]) -> Option<(usize, usize)> {
    let mut from = 0;
    while let Some(pos) = earliest_prefix(haystack, from, &[AWS_AKIA, AWS_ASIA]) {
        if prev_allows_token(haystack, pos) {
            if let Some(span) = aws_at(haystack, pos) {
                return Some(span);
            }
        }
        from = pos + 1;
    }
    None
}

/// Search for the leftmost `google-api-key` span.
pub fn search_google_api_key(haystack: &[u8]) -> Option<(usize, usize)> {
    search_prefixes(haystack, &[GOOGLE_PREFIX], 20, is_ascii_alnum_us_hyphen)
}

/// Search for the leftmost `slack-token` span.
pub fn search_slack_token(haystack: &[u8]) -> Option<(usize, usize)> {
    let mut from = 0;
    while let Some(pos) = find_from(haystack, from, SLACK_PREFIX) {
        if prev_allows_token(haystack, pos) {
            if let Some(end) = slack_end(haystack, pos) {
                return report(pos, end, None, WHOLE_MATCH);
            }
        }
        from = pos + 1;
    }
    None
}

/// Search for the leftmost `gitlab-pat` span.
pub fn search_gitlab_pat(haystack: &[u8]) -> Option<(usize, usize)> {
    search_prefixes(haystack, &[GITLAB_PREFIX], 20, is_ascii_alnum_us_hyphen)
}

/// Search for the leftmost `bearer-token` span.
pub fn search_bearer_token(haystack: &[u8]) -> Option<(usize, usize)> {
    for start in 0..haystack.len() {
        if let Some(span) = bearer_at(haystack, start) {
            return Some(span);
        }
    }
    None
}

/// Search for the leftmost `npm-token` span.
pub fn search_npm_token(haystack: &[u8]) -> Option<(usize, usize)> {
    search_prefixes(haystack, &[NPM_PREFIX], 20, is_ascii_alnum)
}

/// Search for the leftmost `huggingface-token` span.
pub fn search_huggingface_token(haystack: &[u8]) -> Option<(usize, usize)> {
    search_prefixes(haystack, &[HUGGINGFACE_PREFIX], 20, is_ascii_alnum)
}

/// Search for the leftmost `supabase-pat` span.
pub fn search_supabase_pat(haystack: &[u8]) -> Option<(usize, usize)> {
    search_prefixes(haystack, &[SUPABASE_PREFIX], 40, is_lower_hex)
}

/// Search for the leftmost `telegram-bot-token` span.
pub fn search_telegram_bot_token(haystack: &[u8]) -> Option<(usize, usize)> {
    for start in 0..haystack.len() {
        if let Some(span) = telegram_at(haystack, start) {
            return Some(span);
        }
    }
    None
}

/// Search for the leftmost `jwt` span.
pub fn search_jwt(haystack: &[u8]) -> Option<(usize, usize)> {
    let mut from = 0;
    while let Some(pos) = find_from(haystack, from, JWT_PREFIX) {
        if prev_allows_token(haystack, pos) {
            if let Some(end) = jwt_end(haystack, pos) {
                return report(pos, end, None, WHOLE_MATCH);
            }
        }
        from = pos + 1;
    }
    None
}

/// Search for the leftmost `private-key-block` span.
///
/// Group 0 is the whole match, including an optional tail when that tail
/// participates. A tail that fails to reach eight body bytes is omitted.
pub fn search_private_key_block(haystack: &[u8]) -> Option<(usize, usize)> {
    let mut from = 0;
    while let Some(pos) = find_from(haystack, from, PEM_BEGIN) {
        if prev_allows_token(haystack, pos) {
            if let Some(header_end) = private_header_end(haystack, pos + PEM_BEGIN.len()) {
                let tail = optional_pem_tail(haystack, header_end);
                let end = tail.map_or(header_end, |(_, tail_end)| tail_end);
                return report(pos, end, tail, WHOLE_MATCH);
            }
        }
        from = pos + 1;
    }
    None
}

/// Search for the leftmost `generic-credential-assignment` value span.
///
/// The family has no lookbehind. The reported span is capture group 1.
pub fn search_generic_credential_assignment(haystack: &[u8]) -> Option<(usize, usize)> {
    for start in 0..haystack.len() {
        if let Some(span) = generic_at(haystack, start) {
            return Some(span);
        }
    }
    None
}

fn report(
    start: usize,
    end: usize,
    group1: Option<(usize, usize)>,
    group: usize,
) -> Option<(usize, usize)> {
    match group {
        WHOLE_MATCH => Some((start, end)),
        FIRST_CAPTURE => group1,
        _ => None,
    }
}

fn search_prefixes(
    haystack: &[u8],
    prefixes: &[&[u8]],
    min_body: usize,
    class: fn(u8) -> bool,
) -> Option<(usize, usize)> {
    let mut from = 0;
    while let Some(pos) = earliest_prefix(haystack, from, prefixes) {
        if prev_allows_token(haystack, pos) {
            for prefix in prefixes {
                if !haystack
                    .get(pos..)
                    .is_some_and(|rest| rest.starts_with(prefix))
                {
                    continue;
                }
                let body = pos + prefix.len();
                let end = take_while(haystack, body, class);
                if end - body >= min_body {
                    return report(pos, end, None, WHOLE_MATCH);
                }
            }
        }
        from = pos + 1;
    }
    None
}

fn earliest_prefix(haystack: &[u8], from: usize, prefixes: &[&[u8]]) -> Option<usize> {
    let mut best: Option<usize> = None;
    for prefix in prefixes {
        if let Some(pos) = find_from(haystack, from, prefix) {
            if best.is_none_or(|current| pos < current) {
                best = Some(pos);
            }
        }
    }
    best
}

fn find_from(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let tail = haystack.get(from..)?;
    tail.windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| from + offset)
}

fn take_while(haystack: &[u8], start: usize, class: fn(u8) -> bool) -> usize {
    let mut end = start;
    while haystack.get(end).is_some_and(|byte| class(*byte)) {
        end += 1;
    }
    end
}

fn prev_allows_token(haystack: &[u8], index: usize) -> bool {
    if index == 0 {
        return true;
    }
    match haystack.get(index - 1) {
        Some(byte) => !is_ascii_alnum_us_hyphen(*byte),
        None => true,
    }
}

/// Python ASCII `\b`. End of input is a boundary when the previous byte is a word byte.
fn is_word_boundary(haystack: &[u8], index: usize) -> bool {
    let prev_is_word = match index.checked_sub(1) {
        Some(prev) => haystack
            .get(prev)
            .is_some_and(|byte| is_ascii_word_byte(*byte)),
        None => false,
    };
    let next_is_word = haystack
        .get(index)
        .is_some_and(|byte| is_ascii_word_byte(*byte));
    prev_is_word != next_is_word
}

const fn is_ascii_alnum(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

const fn is_ascii_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

const fn is_ascii_alnum_us_hyphen(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

const fn is_ascii_alnum_hyphen(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

const fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

const fn is_upper_or_digit(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte.is_ascii_digit()
}

const fn is_upper_or_space(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte == b' '
}

/// Python bytes `\s`: tab, LF, VT, FF, CR, and space.
const fn is_python_whitespace(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' ')
}

const fn is_space_or_tab(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

const fn is_bearer_body(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(byte, b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'\\' | b'-')
}

const fn is_pem_body(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'_' | b'-')
}

const fn is_generic_value_byte(byte: u8) -> bool {
    !is_python_whitespace(byte)
        && !matches!(
            byte,
            b'"' | b'\'' | b'`' | b',' | b')' | b']' | b'}' | b'\\'
        )
}

fn aws_at(haystack: &[u8], pos: usize) -> Option<(usize, usize)> {
    let prefix_len = if haystack
        .get(pos..)
        .is_some_and(|rest| rest.starts_with(AWS_AKIA))
    {
        AWS_AKIA.len()
    } else if haystack
        .get(pos..)
        .is_some_and(|rest| rest.starts_with(AWS_ASIA))
    {
        AWS_ASIA.len()
    } else {
        return None;
    };
    let body = pos + prefix_len;
    let end = body.checked_add(16)?;
    if end > haystack.len() || !haystack[body..end].iter().copied().all(is_upper_or_digit) {
        return None;
    }
    if !is_word_boundary(haystack, end) {
        return None;
    }
    report(pos, end, None, WHOLE_MATCH)
}

fn slack_end(haystack: &[u8], pos: usize) -> Option<usize> {
    let letter_at = pos.checked_add(SLACK_PREFIX.len())?;
    let hyphen_at = letter_at.checked_add(1)?;
    let letter = haystack.get(letter_at)?;
    let hyphen = haystack.get(hyphen_at)?;
    if !letter.is_ascii_lowercase() || *hyphen != b'-' {
        return None;
    }
    let body = hyphen_at + 1;
    let end = take_while(haystack, body, is_ascii_alnum_hyphen);
    (end - body >= 16).then_some(end)
}

fn bearer_at(haystack: &[u8], start: usize) -> Option<(usize, usize)> {
    if !prev_allows_token(haystack, start)
        || !starts_with_ascii_ignore_case(haystack, start, BEARER_WORD)
    {
        return None;
    }
    let mut index = start + BEARER_WORD.len();
    if !haystack
        .get(index)
        .is_some_and(|byte| is_space_or_tab(*byte))
    {
        return None;
    }
    while haystack
        .get(index)
        .is_some_and(|byte| is_space_or_tab(*byte))
    {
        index += 1;
    }
    let end = take_while(haystack, index, is_bearer_body);
    if end - index < 16 {
        return None;
    }
    report(start, end, None, WHOLE_MATCH)
}

fn telegram_at(haystack: &[u8], start: usize) -> Option<(usize, usize)> {
    if !prev_allows_token(haystack, start) {
        return None;
    }
    let mut digits = 0;
    while digits < 11 {
        let Some(at) = start.checked_add(digits) else {
            break;
        };
        if haystack.get(at).is_some_and(|byte| byte.is_ascii_digit()) {
            digits += 1;
        } else {
            break;
        }
    }
    if !(8..=10).contains(&digits) {
        return None;
    }
    let colon = start + digits;
    if haystack.get(colon) != Some(&b':') {
        return None;
    }
    let body = colon + 1;
    let end = body.checked_add(35)?;
    if end > haystack.len()
        || !haystack[body..end]
            .iter()
            .copied()
            .all(is_ascii_alnum_us_hyphen)
    {
        return None;
    }
    if !is_word_boundary(haystack, end) {
        return None;
    }
    report(start, end, None, WHOLE_MATCH)
}

fn jwt_end(haystack: &[u8], pos: usize) -> Option<usize> {
    let mut index = pos.checked_add(JWT_PREFIX.len())?;
    index = take_min(haystack, index, 10, is_ascii_alnum_us_hyphen)?;
    if haystack.get(index) != Some(&b'.') {
        return None;
    }
    index += 1;
    index = take_min(haystack, index, 10, is_ascii_alnum_us_hyphen)?;
    if haystack.get(index) != Some(&b'.') {
        return None;
    }
    index += 1;
    take_min(haystack, index, 10, is_ascii_alnum_us_hyphen)
}

fn take_min(haystack: &[u8], start: usize, min: usize, class: fn(u8) -> bool) -> Option<usize> {
    let end = take_while(haystack, start, class);
    (end - start >= min).then_some(end)
}

fn private_header_end(haystack: &[u8], after: usize) -> Option<usize> {
    let mut index = after;
    let mut best: Option<usize> = None;
    loop {
        if haystack
            .get(index..)
            .is_some_and(|rest| rest.starts_with(PEM_END))
        {
            best = Some(index + PEM_END.len());
        }
        match haystack.get(index) {
            Some(byte) if is_upper_or_space(*byte) => index += 1,
            _ => break,
        }
    }
    best
}

fn optional_pem_tail(haystack: &[u8], header_end: usize) -> Option<(usize, usize)> {
    let separator_end = consume_pem_separators(haystack, header_end);
    if separator_end == header_end {
        return None;
    }
    let body_end = take_while(haystack, separator_end, is_pem_body);
    if body_end - separator_end >= 8 {
        Some((header_end, body_end))
    } else {
        None
    }
}

fn consume_pem_separators(haystack: &[u8], mut index: usize) -> usize {
    while index < haystack.len() {
        if haystack.get(index) == Some(&b'\\') && haystack.get(index + 1) == Some(&b'n') {
            index += 2;
            continue;
        }
        if haystack
            .get(index)
            .is_some_and(|byte| is_python_whitespace(*byte))
        {
            index += 1;
            continue;
        }
        break;
    }
    index
}

#[derive(Clone, Copy)]
enum Keyword {
    Exact(&'static [u8]),
    OptionalJoin {
        head: &'static [u8],
        tail: &'static [u8],
    },
}

const KEYWORDS: &[Keyword] = &[
    Keyword::Exact(b"password"),
    Keyword::Exact(b"passwd"),
    Keyword::OptionalJoin {
        head: b"api",
        tail: b"key",
    },
    Keyword::OptionalJoin {
        head: b"access",
        tail: b"key",
    },
    Keyword::OptionalJoin {
        head: b"account",
        tail: b"key",
    },
    Keyword::OptionalJoin {
        head: b"client",
        tail: b"secret",
    },
    Keyword::OptionalJoin {
        head: b"private",
        tail: b"key",
    },
    Keyword::OptionalJoin {
        head: b"auth",
        tail: b"token",
    },
    Keyword::Exact(b"secret"),
    Keyword::Exact(b"token"),
];

fn generic_at(haystack: &[u8], start: usize) -> Option<(usize, usize)> {
    for keyword in KEYWORDS.iter().copied() {
        let Some(after_keyword) = keyword_end(haystack, start, keyword) else {
            continue;
        };
        let Some(value) = assignment_value(haystack, after_keyword) else {
            continue;
        };
        return report(start, value.1, Some(value), FIRST_CAPTURE);
    }
    None
}

fn keyword_end(haystack: &[u8], at: usize, keyword: Keyword) -> Option<usize> {
    match keyword {
        Keyword::Exact(literal) => {
            starts_with_ascii_ignore_case(haystack, at, literal).then_some(at + literal.len())
        }
        Keyword::OptionalJoin { head, tail } => {
            if !starts_with_ascii_ignore_case(haystack, at, head) {
                return None;
            }
            let after_head = at + head.len();
            if let Some(b'_' | b'-') = haystack.get(after_head) {
                let after_sep = after_head + 1;
                if starts_with_ascii_ignore_case(haystack, after_sep, tail) {
                    return Some(after_sep + tail.len());
                }
            }
            starts_with_ascii_ignore_case(haystack, after_head, tail)
                .then_some(after_head + tail.len())
        }
    }
}

fn assignment_value(haystack: &[u8], mut index: usize) -> Option<(usize, usize)> {
    index = skip_key_punctuation(haystack, index);
    index = skip_python_whitespace(haystack, index);
    match haystack.get(index) {
        Some(b':' | b'=') => index += 1,
        _ => return None,
    }
    index = skip_python_whitespace(haystack, index);
    index = skip_optional_value_quote(haystack, index);
    index = skip_python_whitespace(haystack, index);
    let start = index;
    while haystack
        .get(index)
        .is_some_and(|byte| is_generic_value_byte(*byte))
    {
        index += 1;
    }
    (index - start >= 8).then_some((start, index))
}

fn skip_python_whitespace(haystack: &[u8], mut index: usize) -> usize {
    while haystack
        .get(index)
        .is_some_and(|byte| is_python_whitespace(*byte))
    {
        index += 1;
    }
    index
}

fn skip_key_punctuation(haystack: &[u8], mut index: usize) -> usize {
    loop {
        let mut cursor = index;
        if haystack.get(cursor) == Some(&b'\\') {
            cursor += 1;
        }
        if matches!(haystack.get(cursor), Some(b'"' | b'\'' | b'.' | b'-')) {
            index = cursor + 1;
            continue;
        }
        break;
    }
    index
}

fn skip_optional_value_quote(haystack: &[u8], index: usize) -> usize {
    let mut cursor = index;
    if haystack.get(cursor) == Some(&b'\\') {
        cursor += 1;
    }
    if matches!(haystack.get(cursor), Some(b'"' | b'\'' | b'`')) {
        cursor + 1
    } else {
        index
    }
}

fn starts_with_ascii_ignore_case(haystack: &[u8], at: usize, literal: &[u8]) -> bool {
    let Some(end) = at.checked_add(literal.len()) else {
        return false;
    };
    match haystack.get(at..end) {
        Some(slice) => slice
            .iter()
            .zip(literal.iter())
            .all(|(got, want)| got.eq_ignore_ascii_case(want)),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        report, search_anthropic_api_key, search_aws_access_key, search_bearer_token,
        search_generic_credential_assignment, search_github_oauth_token, search_github_pat_classic,
        search_github_pat_fine_grained, search_gitlab_pat, search_google_api_key,
        search_huggingface_token, search_jwt, search_npm_token, search_openai_api_key,
        search_openrouter_api_key, search_private_key_block, search_slack_token, search_stripe_key,
        search_stripe_webhook_secret, search_supabase_pat, search_telegram_bot_token,
        FAMILY_LITERALS, SECRET_FAMILIES,
    };

    // Spans are `re.Match.span(group)` from Python 3.11 `re.search` on the pinned
    // patterns, for these exact assemblies. These tests do not call Python.

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

    type SearchFn = fn(&[u8]) -> Option<(usize, usize)>;

    fn assert_glued_rejected(search: SearchFn, prefix: &[u8], body_len: usize, fill: u8) {
        for glue in [b'x', b'1', b'_', b'-'] {
            assert_eq!(
                search(&assembled(&[glue], prefix, body_len, fill, b"")),
                None
            );
        }
    }

    fn pem(lead: &[u8], middle: &[u8], tail: &[u8]) -> Vec<u8> {
        let mut raw = lead.to_vec();
        raw.extend_from_slice(b"-----BEGIN ");
        raw.extend_from_slice(middle);
        raw.extend_from_slice(lit("private-key-block", 0));
        raw.extend_from_slice(tail);
        raw
    }

    fn jwt(lead: &[u8], n1: usize, n2: usize, n3: usize) -> Vec<u8> {
        let mut raw = lead.to_vec();
        raw.extend_from_slice(lit("jwt", 0));
        raw.extend(std::iter::repeat_n(b'a', n1));
        raw.push(b'.');
        raw.extend(std::iter::repeat_n(b'b', n2));
        raw.push(b'.');
        raw.extend(std::iter::repeat_n(b'c', n3));
        raw
    }

    fn assignment(
        lead: &[u8],
        key: &[u8],
        between: &[u8],
        fill: u8,
        len: usize,
        tail: &[u8],
    ) -> Vec<u8> {
        let mut raw = lead.to_vec();
        raw.extend_from_slice(key);
        raw.extend_from_slice(between);
        raw.extend(std::iter::repeat_n(fill, len));
        raw.extend_from_slice(tail);
        raw
    }

    #[test]
    fn absent_group_is_not_a_match() {
        assert_eq!(report(0, 27, None, 0), Some((0, 27)));
        assert_eq!(report(0, 36, None, 1), None);
        assert_eq!(report(0, 36, Some((27, 36)), 0), Some((0, 36)));
        assert_eq!(report(0, 36, Some((27, 36)), 1), Some((27, 36)));
        assert_eq!(report(0, 36, Some((27, 36)), 2), None);
    }

    #[test]
    fn family_order_and_groups_match_pinned_source() {
        let got: Vec<(&str, usize)> = SECRET_FAMILIES
            .iter()
            .map(|family| (family.name, family.group))
            .collect();
        assert_eq!(
            got,
            vec![
                ("anthropic-api-key", 0),
                ("openai-api-key", 0),
                ("openrouter-api-key", 0),
                ("github-pat-classic", 0),
                ("github-pat-fine-grained", 0),
                ("github-oauth-token", 0),
                ("stripe-webhook-secret", 0),
                ("stripe-key", 0),
                ("aws-access-key", 0),
                ("google-api-key", 0),
                ("slack-token", 0),
                ("gitlab-pat", 0),
                ("bearer-token", 0),
                ("npm-token", 0),
                ("huggingface-token", 0),
                ("supabase-pat", 0),
                ("telegram-bot-token", 0),
                ("jwt", 0),
                ("private-key-block", 0),
                ("generic-credential-assignment", 1),
            ]
        );
    }

    #[test]
    fn literal_keys_keep_insertion_order() {
        assert_eq!(FAMILY_LITERALS.len(), 18);
        assert_eq!(lit("anthropic-api-key", 0), b"sk-ant-");
        assert_eq!(lit("openai-api-key", 0), b"sk-");
        assert_eq!(lit("openrouter-api-key", 0), b"sk-or-v1-");
        assert_eq!(lit("github-pat-classic", 0), b"ghp_");
        assert_eq!(lit("github-pat-fine-grained", 0), b"github_pat_");
        assert_eq!(lit("github-oauth-token", 0), b"gho_");
        assert_eq!(lit("github-oauth-token", 1), b"ghs_");
        assert_eq!(lit("github-oauth-token", 2), b"ghr_");
        assert_eq!(lit("github-oauth-token", 3), b"ghu_");
        assert_eq!(lit("stripe-webhook-secret", 0), b"whsec_");
        assert_eq!(lit("stripe-key", 0), b"sk_live_");
        assert_eq!(lit("stripe-key", 1), b"sk_test_");
        assert_eq!(lit("stripe-key", 2), b"rk_live_");
        assert_eq!(lit("stripe-key", 3), b"rk_test_");
        assert_eq!(lit("aws-access-key", 0), b"AKIA");
        assert_eq!(lit("aws-access-key", 1), b"ASIA");
        assert_eq!(lit("google-api-key", 0), b"AIza");
        assert_eq!(lit("slack-token", 0), b"xox");
        assert_eq!(lit("gitlab-pat", 0), b"glpat-");
        assert_eq!(lit("bearer-token", 0), b"bearer");
        assert_eq!(lit("npm-token", 0), b"npm_");
        assert_eq!(lit("huggingface-token", 0), b"hf_");
        assert_eq!(lit("supabase-pat", 0), b"sbp_");
        assert_eq!(lit("jwt", 0), b"eyJ");
        assert_eq!(lit("private-key-block", 0), b"PRIVATE KEY-----");
        let names: Vec<&str> = FAMILY_LITERALS.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            vec![
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
                "jwt",
                "private-key-block",
            ]
        );
        assert!(names.iter().all(|name| {
            *name != "telegram-bot-token" && *name != "generic-credential-assignment"
        }));
    }

    #[test]
    fn table_search_is_the_named_function() {
        let expected: [SearchFn; 20] = [
            search_anthropic_api_key,
            search_openai_api_key,
            search_openrouter_api_key,
            search_github_pat_classic,
            search_github_pat_fine_grained,
            search_github_oauth_token,
            search_stripe_webhook_secret,
            search_stripe_key,
            search_aws_access_key,
            search_google_api_key,
            search_slack_token,
            search_gitlab_pat,
            search_bearer_token,
            search_npm_token,
            search_huggingface_token,
            search_supabase_pat,
            search_telegram_bot_token,
            search_jwt,
            search_private_key_block,
            search_generic_credential_assignment,
        ];
        assert_eq!(SECRET_FAMILIES.len(), expected.len());
        for (family, function) in SECRET_FAMILIES.iter().zip(expected) {
            assert!(std::ptr::fn_addr_eq(family.search, function));
        }
    }

    #[test]
    fn empty_haystack_has_no_match() {
        for family in SECRET_FAMILIES {
            assert_eq!((family.search)(b""), None);
        }
    }

    #[test]
    fn anthropic_api_key_matches_pinned_re_search() {
        let prefix = lit("anthropic-api-key", 0);
        assert_eq!(
            search_anthropic_api_key(&assembled(b"", prefix, 20, b'a', b"")),
            Some((0, 27))
        );
        assert_eq!(
            search_anthropic_api_key(&assembled(b"..", prefix, 20, b'a', b"")),
            Some((2, 29))
        );
        assert_eq!(
            search_anthropic_api_key(&assembled(b".", prefix, 20, b'A', b"Z")),
            Some((1, 29))
        );
        assert_eq!(
            search_anthropic_api_key(&assembled(b" ", prefix, 20, b'_', b"")),
            Some((1, 28))
        );
        assert_eq!(
            search_anthropic_api_key(&assembled(b" ", prefix, 20, b'-', b"")),
            Some((1, 28))
        );
        assert_eq!(
            search_anthropic_api_key(&assembled(b"zz ", prefix, 20, b'a', b"")),
            Some((3, 30))
        );
        assert_eq!(
            search_anthropic_api_key(&assembled(b"", prefix, 19, b'a', b"")),
            None
        );
        assert_glued_rejected(search_anthropic_api_key, prefix, 20, b'a');
    }

    #[test]
    fn openai_api_key_matches_pinned_re_search() {
        let prefix = lit("openai-api-key", 0);
        assert_eq!(
            search_openai_api_key(&assembled(b"", prefix, 20, b'a', b"")),
            Some((0, 23))
        );
        assert_eq!(
            search_openai_api_key(&assembled(b"[]", prefix, 20, b'B', b"-tail")),
            Some((2, 25))
        );
        assert_eq!(
            search_openai_api_key(&assembled(b"", prefix, 19, b'a', b"")),
            None
        );
        assert_eq!(
            search_openai_api_key(&assembled(b"", lit("anthropic-api-key", 0), 20, b'a', b"")),
            None
        );
        let mut underscore_stops = assembled(b"", prefix, 19, b'a', b"_");
        underscore_stops.extend(std::iter::repeat_n(b'a', 20));
        assert_eq!(search_openai_api_key(&underscore_stops), None);
        let mut later = assembled(b"nope ", prefix, 19, b'a', b" ");
        later.extend_from_slice(prefix);
        later.extend(std::iter::repeat_n(b'b', 20));
        assert_eq!(search_openai_api_key(&later), Some((28, 51)));
        let mut greedy = assembled(b"", prefix, 20, b'a', b"");
        greedy.extend_from_slice(prefix);
        greedy.extend(std::iter::repeat_n(b'b', 20));
        assert_eq!(search_openai_api_key(&greedy), Some((0, 25)));
        assert_eq!(
            search_openai_api_key(&assembled(b"sk-", prefix, 20, b'a', b"")),
            None
        );
        assert_glued_rejected(search_openai_api_key, prefix, 20, b'a');
    }

    #[test]
    fn openrouter_api_key_matches_pinned_re_search() {
        let prefix = lit("openrouter-api-key", 0);
        assert_eq!(
            search_openrouter_api_key(&assembled(b"", prefix, 48, b'a', b"")),
            Some((0, 57))
        );
        assert_eq!(
            search_openrouter_api_key(&assembled(b"\n", prefix, 48, b'0', b"G")),
            Some((1, 58))
        );
        assert_eq!(
            search_openrouter_api_key(&assembled(b"", prefix, 47, b'f', b"")),
            None
        );
        assert_eq!(
            search_openrouter_api_key(&assembled(b"", prefix, 48, b'A', b"")),
            None
        );
        assert_glued_rejected(search_openrouter_api_key, prefix, 48, b'a');
    }

    #[test]
    fn github_pat_classic_matches_pinned_re_search() {
        let prefix = lit("github-pat-classic", 0);
        assert_eq!(
            search_github_pat_classic(&assembled(b"", prefix, 36, b'a', b"")),
            Some((0, 40))
        );
        assert_eq!(
            search_github_pat_classic(&assembled(b" pre:", prefix, 36, b'Z', b"")),
            Some((5, 45))
        );
        assert_eq!(
            search_github_pat_classic(&assembled(b"", prefix, 35, b'a', b"")),
            None
        );
        assert_eq!(
            search_github_pat_classic(&assembled(b"", prefix, 35, b'a', b"_")),
            None
        );
        assert_glued_rejected(search_github_pat_classic, prefix, 36, b'a');
    }

    #[test]
    fn github_pat_fine_grained_matches_pinned_re_search() {
        let prefix = lit("github-pat-fine-grained", 0);
        assert_eq!(
            search_github_pat_fine_grained(&assembled(b"", prefix, 22, b'a', b"")),
            Some((0, 33))
        );
        assert_eq!(
            search_github_pat_fine_grained(&assembled(b":", prefix, 22, b'_', b"")),
            Some((1, 34))
        );
        assert_eq!(
            search_github_pat_fine_grained(&assembled(b"", prefix, 21, b'a', b"")),
            None
        );
        assert_glued_rejected(search_github_pat_fine_grained, prefix, 22, b'a');
    }

    #[test]
    fn github_oauth_token_matches_pinned_re_search() {
        for index in 0..4 {
            assert_eq!(
                search_github_oauth_token(&assembled(
                    b" ",
                    lit("github-oauth-token", index),
                    36,
                    b'a',
                    b""
                )),
                Some((1, 41))
            );
        }
        assert_eq!(
            search_github_oauth_token(&assembled(
                b" ",
                lit("github-pat-classic", 0),
                36,
                b'a',
                b""
            )),
            None
        );
        assert_eq!(
            search_github_oauth_token(&assembled(b" ", b"gha_", 36, b'a', b"")),
            None
        );
        assert_eq!(
            search_github_oauth_token(&assembled(b"", lit("github-oauth-token", 0), 35, b'a', b"")),
            None
        );
        assert_glued_rejected(
            search_github_oauth_token,
            lit("github-oauth-token", 0),
            36,
            b'a',
        );
    }

    #[test]
    fn stripe_webhook_secret_matches_pinned_re_search() {
        let prefix = lit("stripe-webhook-secret", 0);
        assert_eq!(
            search_stripe_webhook_secret(&assembled(b"", prefix, 24, b'a', b"")),
            Some((0, 30))
        );
        assert_eq!(
            search_stripe_webhook_secret(&assembled(b".", prefix, 24, b'0', b"")),
            Some((1, 31))
        );
        assert_eq!(
            search_stripe_webhook_secret(&assembled(b"", prefix, 23, b'a', b"")),
            None
        );
        assert_glued_rejected(search_stripe_webhook_secret, prefix, 24, b'a');
    }

    #[test]
    fn stripe_key_matches_pinned_re_search() {
        for index in 0..4 {
            assert_eq!(
                search_stripe_key(&assembled(b" ", lit("stripe-key", index), 16, b'a', b"")),
                Some((1, 25))
            );
        }
        assert_eq!(
            search_stripe_key(&assembled(b"", lit("stripe-key", 0), 16, b'a', b"")),
            Some((0, 24))
        );
        assert_eq!(
            search_stripe_key(&assembled(b"", lit("stripe-key", 0), 15, b'a', b"")),
            None
        );
        assert_glued_rejected(search_stripe_key, lit("stripe-key", 0), 16, b'a');
    }

    #[test]
    fn aws_access_key_matches_pinned_re_search() {
        let akia = lit("aws-access-key", 0);
        let asia = lit("aws-access-key", 1);
        assert_eq!(
            search_aws_access_key(&assembled(b"", akia, 16, b'0', b"")),
            Some((0, 20))
        );
        assert_eq!(
            search_aws_access_key(&assembled(b" id:", asia, 16, b'A', b" ")),
            Some((4, 24))
        );
        assert_eq!(
            search_aws_access_key(&assembled(b"", akia, 16, b'Z', b"")),
            Some((0, 20))
        );
        assert_eq!(
            search_aws_access_key(&assembled(b"", akia, 16, b'B', b"-")),
            Some((0, 20))
        );
        assert_eq!(
            search_aws_access_key(&assembled(b".", akia, 16, b'0', b"")),
            Some((1, 21))
        );
        assert_eq!(
            search_aws_access_key(&assembled(b"", akia, 15, b'0', b"")),
            None
        );
        assert_eq!(
            search_aws_access_key(&assembled(b"", akia, 17, b'0', b"")),
            None
        );
        assert_eq!(
            search_aws_access_key(&assembled(b"", akia, 16, b'a', b"")),
            None
        );
        assert_eq!(
            search_aws_access_key(&assembled(b"", akia, 16, b'B', b"_")),
            None
        );
        assert_eq!(
            search_aws_access_key(&assembled(b"", b"akia", 16, b'0', b"")),
            None
        );
        assert_glued_rejected(search_aws_access_key, akia, 16, b'0');
    }

    #[test]
    fn google_api_key_matches_pinned_re_search() {
        let prefix = lit("google-api-key", 0);
        assert_eq!(
            search_google_api_key(&assembled(b"", prefix, 20, b'a', b"")),
            Some((0, 24))
        );
        let mut mixed = assembled(b"\t", prefix, 10, b'_', b"");
        mixed.extend(std::iter::repeat_n(b'-', 10));
        assert_eq!(search_google_api_key(&mixed), Some((1, 25)));
        assert_eq!(
            search_google_api_key(&assembled(b"", prefix, 19, b'a', b"")),
            None
        );
        assert_glued_rejected(search_google_api_key, prefix, 20, b'a');
    }

    #[test]
    fn slack_token_matches_pinned_re_search() {
        let mut bot = lit("slack-token", 0).to_vec();
        bot.push(b'b');
        bot.push(b'-');
        assert_eq!(
            search_slack_token(&assembled(b"", &bot, 16, b'a', b"")),
            Some((0, 21))
        );
        let mut user = lit("slack-token", 0).to_vec();
        user.push(b'p');
        user.push(b'-');
        assert_eq!(
            search_slack_token(&assembled(b"(", &user, 16, b'-', b"!")),
            Some((1, 22))
        );
        let mut zee = lit("slack-token", 0).to_vec();
        zee.push(b'z');
        zee.push(b'-');
        assert_eq!(
            search_slack_token(&assembled(b" ", &zee, 16, b'A', b"")),
            Some((1, 22))
        );
        let mut upper = lit("slack-token", 0).to_vec();
        upper.push(b'B');
        upper.push(b'-');
        assert_eq!(
            search_slack_token(&assembled(b"", &upper, 16, b'a', b"")),
            None
        );
        let mut short = lit("slack-token", 0).to_vec();
        short.push(b'a');
        short.push(b'-');
        assert_eq!(
            search_slack_token(&assembled(b"", &short, 15, b'a', b"")),
            None
        );
        assert_glued_rejected(search_slack_token, &bot, 16, b'a');
    }

    #[test]
    fn gitlab_pat_matches_pinned_re_search() {
        let prefix = lit("gitlab-pat", 0);
        assert_eq!(
            search_gitlab_pat(&assembled(b"", prefix, 20, b'a', b"")),
            Some((0, 26))
        );
        assert_eq!(
            search_gitlab_pat(&assembled(b" ", prefix, 20, b'-', b"")),
            Some((1, 27))
        );
        assert_eq!(
            search_gitlab_pat(&assembled(b"", prefix, 19, b'a', b"")),
            None
        );
        assert_glued_rejected(search_gitlab_pat, prefix, 20, b'a');
    }

    #[test]
    fn bearer_token_matches_pinned_re_search() {
        let word = lit("bearer-token", 0);
        let mut minimum = word.to_vec();
        minimum.push(b' ');
        assert_eq!(
            search_bearer_token(&assembled(b"", &minimum, 16, b'a', b"")),
            Some((0, 23))
        );
        let mut mixed_case = b"\nBeArEr\t".to_vec();
        mixed_case.extend(std::iter::repeat_n(b'a', 16));
        assert_eq!(search_bearer_token(&mixed_case), Some((1, 24)));
        let mut symbols = b"BEARER   ".to_vec();
        symbols.extend(std::iter::repeat_n(b'.', 8));
        symbols.extend_from_slice(b"_~+/=");
        symbols.push(b'\\');
        symbols.extend(std::iter::repeat_n(b'-', 2));
        assert_eq!(search_bearer_token(&symbols), Some((0, 25)));
        let mut slashes = word.to_vec();
        slashes.push(b' ');
        slashes.extend(std::iter::repeat_n(b'\\', 16));
        assert_eq!(search_bearer_token(&slashes), Some((0, 23)));
        let mut newline = word.to_vec();
        newline.push(b'\n');
        newline.extend(std::iter::repeat_n(b'a', 16));
        assert_eq!(search_bearer_token(&newline), None);
        assert_eq!(
            search_bearer_token(&assembled(b"", &minimum, 15, b'a', b"")),
            None
        );
        let mut nospace = word.to_vec();
        nospace.extend(std::iter::repeat_n(b'a', 16));
        assert_eq!(search_bearer_token(&nospace), None);
        let mut spaces = word.to_vec();
        spaces.push(b' ');
        spaces.extend(std::iter::repeat_n(b' ', 16));
        assert_eq!(search_bearer_token(&spaces), None);
        assert_glued_rejected(search_bearer_token, &minimum, 16, b'a');
    }

    #[test]
    fn npm_token_matches_pinned_re_search() {
        let prefix = lit("npm-token", 0);
        assert_eq!(
            search_npm_token(&assembled(b"", prefix, 20, b'a', b"")),
            Some((0, 24))
        );
        assert_eq!(
            search_npm_token(&assembled(b".", prefix, 20, b'0', b"")),
            Some((1, 25))
        );
        assert_eq!(
            search_npm_token(&assembled(b"", prefix, 19, b'a', b"")),
            None
        );
        assert_glued_rejected(search_npm_token, prefix, 20, b'a');
    }

    #[test]
    fn huggingface_token_matches_pinned_re_search() {
        let prefix = lit("huggingface-token", 0);
        assert_eq!(
            search_huggingface_token(&assembled(b"", prefix, 20, b'a', b"")),
            Some((0, 23))
        );
        assert_eq!(
            search_huggingface_token(&assembled(b" ", prefix, 20, b'Z', b"")),
            Some((1, 24))
        );
        assert_eq!(
            search_huggingface_token(&assembled(b"", prefix, 19, b'a', b"")),
            None
        );
        assert_glued_rejected(search_huggingface_token, prefix, 20, b'a');
    }

    #[test]
    fn supabase_pat_matches_pinned_re_search() {
        let prefix = lit("supabase-pat", 0);
        assert_eq!(
            search_supabase_pat(&assembled(b"", prefix, 40, b'a', b"")),
            Some((0, 44))
        );
        assert_eq!(
            search_supabase_pat(&assembled(b":", prefix, 40, b'f', b"A")),
            Some((1, 45))
        );
        assert_eq!(
            search_supabase_pat(&assembled(b"", prefix, 39, b'0', b"")),
            None
        );
        assert_eq!(
            search_supabase_pat(&assembled(b"", prefix, 40, b'A', b"")),
            None
        );
        assert_glued_rejected(search_supabase_pat, prefix, 40, b'a');
    }

    #[test]
    fn telegram_bot_token_matches_pinned_re_search() {
        let mut eight = b"12345678:".to_vec();
        eight.extend(std::iter::repeat_n(b'a', 35));
        assert_eq!(search_telegram_bot_token(&eight), Some((0, 44)));
        let mut nine = b"123456789:".to_vec();
        nine.extend(std::iter::repeat_n(b'b', 35));
        assert_eq!(search_telegram_bot_token(&nine), Some((0, 45)));
        let mut ten = b" 1234567890:".to_vec();
        ten.extend(std::iter::repeat_n(b'c', 35));
        assert_eq!(search_telegram_bot_token(&ten), Some((1, 47)));
        let mut dotted = b".12345678:".to_vec();
        dotted.extend(std::iter::repeat_n(b'_', 35));
        assert_eq!(search_telegram_bot_token(&dotted), Some((1, 45)));
        let mut hyphen_after = eight.clone();
        hyphen_after.push(b'-');
        assert_eq!(search_telegram_bot_token(&hyphen_after), Some((0, 44)));
        let mut underscore_after = eight.clone();
        underscore_after.push(b'_');
        assert_eq!(search_telegram_bot_token(&underscore_after), None);
        let mut end_hyphen = b"12345678:".to_vec();
        end_hyphen.extend(std::iter::repeat_n(b'a', 34));
        end_hyphen.push(b'-');
        assert_eq!(search_telegram_bot_token(&end_hyphen), None);
        let mut hyphen_then_word = end_hyphen.clone();
        hyphen_then_word.push(b'x');
        assert_eq!(search_telegram_bot_token(&hyphen_then_word), Some((0, 44)));
        let mut seven = b"1234567:".to_vec();
        seven.extend(std::iter::repeat_n(b'a', 35));
        assert_eq!(search_telegram_bot_token(&seven), None);
        let mut eleven = b"12345678901:".to_vec();
        eleven.extend(std::iter::repeat_n(b'a', 35));
        assert_eq!(search_telegram_bot_token(&eleven), None);
        let mut short_body = b"12345678:".to_vec();
        short_body.extend(std::iter::repeat_n(b'a', 34));
        assert_eq!(search_telegram_bot_token(&short_body), None);
        let mut long_body = b"12345678:".to_vec();
        long_body.extend(std::iter::repeat_n(b'a', 36));
        assert_eq!(search_telegram_bot_token(&long_body), None);
        for glue in [b'x', b'_', b'-'] {
            let mut raw = vec![glue];
            raw.extend_from_slice(b"12345678:");
            raw.extend(std::iter::repeat_n(b'a', 35));
            assert_eq!(search_telegram_bot_token(&raw), None);
        }
    }

    #[test]
    fn jwt_matches_pinned_re_search() {
        assert_eq!(search_jwt(&jwt(b"", 10, 10, 10)), Some((0, 35)));
        assert_eq!(search_jwt(&jwt(b"\r", 11, 12, 13)), Some((1, 42)));
        let mut symbols = b" ".to_vec();
        symbols.extend_from_slice(lit("jwt", 0));
        symbols.extend(std::iter::repeat_n(b'_', 10));
        symbols.push(b'.');
        symbols.extend(std::iter::repeat_n(b'-', 10));
        symbols.push(b'.');
        symbols.extend(std::iter::repeat_n(b'Z', 10));
        assert_eq!(search_jwt(&symbols), Some((1, 36)));
        assert_eq!(search_jwt(&jwt(b"", 9, 10, 10)), None);
        assert_eq!(search_jwt(&jwt(b"", 10, 9, 10)), None);
        assert_eq!(search_jwt(&jwt(b"", 10, 10, 9)), None);
        for glue in [b'x', b'1', b'_', b'-'] {
            assert_eq!(search_jwt(&jwt(&[glue], 10, 10, 10)), None);
        }
    }

    #[test]
    fn private_key_block_matches_pinned_re_search() {
        assert_eq!(search_private_key_block(&pem(b"", b"", b"")), Some((0, 27)));
        assert_eq!(
            search_private_key_block(&pem(b"", b"RSA ", b"")),
            Some((0, 31))
        );
        assert_eq!(
            search_private_key_block(&pem(b"", b"OPENSSH ", b"")),
            Some((0, 35))
        );
        assert_eq!(
            search_private_key_block(&pem(b"", b"EC ", b"")),
            Some((0, 30))
        );
        assert_eq!(
            search_private_key_block(&pem(b"", b" ", b"")),
            Some((0, 28))
        );
        assert_eq!(
            search_private_key_block(&pem(b"", b"PRIVATE ", b"")),
            Some((0, 35))
        );
        let mut newline_tail = pem(b"", b"", b"\n");
        newline_tail.extend(std::iter::repeat_n(b'A', 8));
        assert_eq!(search_private_key_block(&newline_tail), Some((0, 36)));
        let mut escaped_tail = pem(b"", b"", b"");
        escaped_tail.push(b'\\');
        escaped_tail.push(b'n');
        escaped_tail.extend(std::iter::repeat_n(b'A', 8));
        assert_eq!(search_private_key_block(&escaped_tail), Some((0, 37)));
        let mut short_tail = pem(b"", b"", b"\n");
        short_tail.extend(std::iter::repeat_n(b'A', 7));
        assert_eq!(search_private_key_block(&short_tail), Some((0, 27)));
        let mut mixed = pem(b" ", b"RSA ", b"\n");
        mixed.push(b'\\');
        mixed.push(b'n');
        mixed.push(b'\t');
        mixed.extend(std::iter::repeat_n(b'+', 4));
        mixed.extend(std::iter::repeat_n(b'/', 4));
        mixed.extend_from_slice(b"==");
        assert_eq!(search_private_key_block(&mixed), Some((1, 46)));
        let mut tail_then_junk = newline_tail.clone();
        tail_then_junk.extend_from_slice(b"\nMORE");
        assert_eq!(search_private_key_block(&tail_then_junk), Some((0, 36)));
        let mut bare_slash = pem(b"", b"", b"\\");
        bare_slash.extend(std::iter::repeat_n(b'A', 8));
        assert_eq!(search_private_key_block(&bare_slash), Some((0, 27)));
        let mut whitespace = pem(b"", b"", b"\r\n\x0c\x0b ");
        whitespace.extend(std::iter::repeat_n(b'a', 8));
        assert_eq!(search_private_key_block(&whitespace), Some((0, 40)));
        let mut lower = b"-----BEGIN ".to_vec();
        lower.extend_from_slice(b"private KEY-----");
        assert_eq!(search_private_key_block(&lower), None);
        let mut truncated = b"-----BEGIN ".to_vec();
        truncated.extend_from_slice(b"PRIVATE KEY----");
        assert_eq!(search_private_key_block(&truncated), None);
        for glue in [b'x', b'1', b'_', b'-'] {
            assert_eq!(search_private_key_block(&pem(&[glue], b"", b"")), None);
        }
    }

    #[test]
    fn generic_keywords_match_pinned_re_search() {
        let search = search_generic_credential_assignment;
        assert_eq!(
            search(&assignment(b"", b"password", b"=", b'a', 8, b"")),
            Some((9, 17))
        );
        assert_eq!(
            search(&assignment(b"xx ", b"password", b"=", b'b', 8, b"")),
            Some((12, 20))
        );
        assert_eq!(
            search(&assignment(b"x", b"password", b"=", b'a', 8, b"")),
            Some((10, 18))
        );
        assert_eq!(
            search(&assignment(b"", b"password", b"=", b'a', 7, b"")),
            None
        );
        assert_eq!(
            search(&assignment(b"", b"PaSsWoRd", b" = ", b'Q', 8, b"")),
            Some((11, 19))
        );
        assert_eq!(
            search(&assignment(b"", b"api_key", b": ", b'a', 8, b"")),
            Some((9, 17))
        );
        assert_eq!(
            search(&assignment(b"", b"api-key", b"=", b'a', 8, b"")),
            Some((8, 16))
        );
        assert_eq!(
            search(&assignment(b"", b"apikey", b"=", b'a', 8, b"")),
            Some((7, 15))
        );
        assert_eq!(
            search(&assignment(b"", b"api__key", b"=", b'a', 8, b"")),
            None
        );
        assert_eq!(
            search(&assignment(
                b"",
                b"aws_secret_access_key",
                b"=",
                b'a',
                8,
                b""
            )),
            Some((22, 30))
        );
        assert_eq!(
            search(&assignment(b"", b"token_count", b"=", b'a', 8, b"")),
            None
        );
        assert_eq!(
            search(&assignment(b"", b"token_endpoint", b"=", b'a', 8, b"")),
            None
        );
        assert_eq!(
            search(&assignment(b"", b"secretary", b"=", b'a', 8, b"")),
            None
        );
        assert_eq!(
            search(&assignment(b"", b"id_token_hint", b"=", b'a', 8, b"")),
            None
        );
        assert_eq!(
            search(&assignment(b"", b"passwd", b"=", b'a', 8, b"")),
            Some((7, 15))
        );
        assert_eq!(
            search(&assignment(b"", b"client_secret", b"=\t", b'a', 8, b"")),
            Some((15, 23))
        );
        assert_eq!(
            search(&assignment(b"", b"client-secret", b"=", b'a', 8, b"")),
            Some((14, 22))
        );
        assert_eq!(
            search(&assignment(b"", b"clientsecret", b"=", b'a', 8, b"")),
            Some((13, 21))
        );
        assert_eq!(
            search(&assignment(b"", b"private_key", b"=", b'a', 8, b"")),
            Some((12, 20))
        );
        assert_eq!(
            search(&assignment(b"", b"auth_token", b"=", b'a', 8, b"")),
            Some((11, 19))
        );
        assert_eq!(
            search(&assignment(b"", b"account-key", b"=", b'a', 8, b"")),
            Some((12, 20))
        );
        assert_eq!(
            search(&assignment(b"", b"accesskey", b"=", b'a', 8, b"")),
            Some((10, 18))
        );
        assert_eq!(
            search(&assignment(b"", b"ACCESS-KEY", b"=", b'a', 8, b"")),
            Some((11, 19))
        );
        assert_eq!(
            search(&assignment(b"", b"my_secret", b"=", b'c', 8, b"")),
            Some((10, 18))
        );
        assert_eq!(
            search(&assignment(b"", b"secret", b":", b'a', 8, b"")),
            Some((7, 15))
        );
        for glue in [b'x', b'1', b'_', b'-'] {
            assert_eq!(
                search(&assignment(&[glue], b"password", b"=", b'a', 8, b"")),
                Some((10, 18))
            );
        }
    }

    #[test]
    fn generic_value_span_matches_pinned_re_search() {
        let search = search_generic_credential_assignment;
        let mut json = b"{\"token\": \"".to_vec();
        json.extend(std::iter::repeat_n(b'a', 8));
        json.push(b'"');
        json.push(b'}');
        assert_eq!(search(&json), Some((11, 19)));

        let mut escaped = vec![
            b'\\', b'"', b'p', b'a', b's', b's', b'w', b'o', b'r', b'd', b'\\', b'"', b':', b' ',
            b'\\', b'"',
        ];
        escaped.extend(std::iter::repeat_n(b'a', 8));
        escaped.push(b'\\');
        escaped.push(b'"');
        assert_eq!(search(&escaped), Some((16, 24)));

        let mut quotes = b"token='".to_vec();
        quotes.extend(std::iter::repeat_n(b'a', 8));
        quotes.push(b'\'');
        assert_eq!(search(&quotes), Some((7, 15)));
        let mut ticks = b"token=`".to_vec();
        ticks.extend(std::iter::repeat_n(b'a', 8));
        ticks.push(b'`');
        assert_eq!(search(&ticks), Some((7, 15)));
        assert_eq!(
            search(&assignment(b"", b"token", b"=", b'a', 8, b",more")),
            Some((6, 14))
        );
        let mut open_paren = b"token=(".to_vec();
        open_paren.extend(std::iter::repeat_n(b'a', 8));
        open_paren.push(b')');
        assert_eq!(search(&open_paren), Some((6, 15)));
        assert_eq!(
            search(&assignment(b"", b"token", b"=", b'a', 8, b")")),
            Some((6, 14))
        );
        assert_eq!(
            search(&assignment(b"", b"token", b"=", b'a', 8, b" tail")),
            Some((6, 14))
        );
        assert_eq!(
            search(&assignment(b"", b"token", b".=", b'a', 8, b"")),
            Some((7, 15))
        );
        assert_eq!(
            search(&assignment(b"", b"token", b"\\=", b'a', 8, b"")),
            None
        );
        let mut first = assignment(b"", b"token", b"=", b'a', 8, b" token=");
        first.extend(std::iter::repeat_n(b'b', 8));
        assert_eq!(search(&first), Some((6, 14)));
        let mut word = b"password=".to_vec();
        word.extend_from_slice(b"password");
        assert_eq!(search(&word), Some((9, 17)));
        let mut quoted = b"api_key = \"".to_vec();
        quoted.extend(std::iter::repeat_n(b'a', 8));
        quoted.push(b'"');
        assert_eq!(search(&quoted), Some((11, 19)));
        assert_eq!(
            search(&assignment(b"", b"password", b"\x0b=", b'a', 8, b"")),
            Some((10, 18))
        );
        assert_eq!(search(b""), None);
    }
}
