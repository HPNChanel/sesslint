# Verify an outcome against a contract (OutcomeGuard)

<!-- next-release: file -->

`sesslint outcome` answers a different question from `sesslint check`. A clean
session ledger shows the transcript is structurally sound. It does not show
that the work produced the declared result at the target system. OutcomeGuard
reconciles the work items in a **source** snapshot against the records in a
**target** snapshot, using a declared **contract**. It reports both questions
side by side and never merges them.

The command runs offline and is read-only. It reads only local files. It never
calls a target system, never edits an agent store and never reads the wall
clock.

```console
sesslint outcome contract.json --explain
sesslint outcome contract.json --source orders.csv --target shipments.json
sesslint outcome contract.json --source orders.csv --source-completeness complete \
    --target shipments.jsonl --target-completeness complete \
    --target-observed-at 2026-10-20T12:00:00Z --json -o outcome.json
```

You can run the synthetic example offline. The starter kit ships it in
`examples/outcome/` (contract, source CSV and a complete target snapshot). The
repository holds the same scenario, with a raw JSONL target and the expected
report, in
[`fixtures/outcome/orders/`](https://github.com/HPNChanel/sesslint/tree/main/fixtures/outcome/orders).
The orders and shipments in it are invented.

## Exit codes

| Exit | Meaning |
| :-: | --- |
| `0` | The outcome is `VERIFIED`. |
| `1` | The check completed and the outcome is anything else: `VIOLATED`, `PENDING`, `INCONCLUSIVE`, `NOT_APPLICABLE` or `NOT_EVALUATED`. |
| `2` | Usage or input error, for example an invalid contract, an unreadable snapshot, contradictory metadata or no evaluation instant. |

In JSON output, `run_status: "completed"` says the check itself ran. The
`outcome` field holds the verdict.

## What can be proven

Every verdict is limited to the supplied observations.

- **Absence needs a complete, current target.** A result is `missing`
  (`VIOLATED`) only when the target snapshot meets all three conditions:
  - it is declared `complete`
  - its `observed_at` is at or after the item's deadline
  - it has no rows without a usable key

  If any is missing, the verdict is `INCONCLUSIVE` and names the missing proof,
  for example `target_incomplete` or `target_stale`.
- **Upper bounds need a complete, fully keyed target.** Duplicates in a partial
  snapshot can be paging artifacts, so they are reported as
  `duplicates_unconfirmed`, not `too_many`. A count within `max` is confirmed
  only when the snapshot is complete (else `upper_bound_unproven`) and every
  target row has a usable key (else `target_unkeyed_rows`), because a keyless
  row may be one more record for the item.
- **Lateness needs a complete target.** A late completion in a partial snapshot
  is `late_unconfirmed`, because an earlier record may not be in the snapshot.
  `late` also needs the deadline to have passed at the evaluation instant;
  before that the item is `PENDING`.
- **Completion times must be plausible.** With `basis: "target_time"`, a
  completion time counts only if it is at or after the source event, at or
  before the evaluation instant, and not after the target snapshot's
  `observed_at`. A counted time at or before the deadline verifies. A time
  before the source event cannot be this item's result
  (`completion_before_event`), and a time after the observation was never
  observed (`completion_after_observation`). Both are `INCONCLUSIVE`, never
  `VERIFIED` and never `late`. With `basis: "observation"`, a target snapshot
  observed before the source event gives `completion_before_event`.
- **Numbers compare exactly.** Integers of up to 4300 digits compare exactly
  and decimals compare as written, so CSV `0.1` equals JSON `0.1`, and
  `9007199254740993` differs from `9007199254740992`. A contract number with a
  fraction or exponent must equal a 64-bit float exactly (up to 15 significant
  digits are always safe for magnitudes from 1e-307 to 1e308); otherwise the
  contract is rejected, so write large bounds as integers. A JSON number in a
  contract or snapshot may have at most 4300 characters, not counting a minus
  sign, and a JSON snapshot number's exponent at most 6 digits. A longer
  number makes the file invalid ("number out of range"), whatever
  `PYTHONINTMAXSTRDIGITS` is set to. The one exception: if
  `PYTHONINTMAXSTRDIGITS` (or `sys.set_int_max_str_digits`) lowers Python's
  limit below 4300 digits, a contract integer longer than that limit cannot be
  fingerprinted, so the contract is rejected.
- **Unevaluated items never count as passes.** If an item could not be
  evaluated, for example because no target record exists and the contract has
  no `exists` or `count` condition, a run that would otherwise verify is
  `INCONCLUSIVE` (`some_items_not_evaluated`).
- **Source coverage needs a complete source.** If every listed item verifies but
  the source is not declared `complete`, the outcome is `INCONCLUSIVE`
  (`source_coverage_unproven`). Items the source did not list were never
  checked.
- **Keys match exactly.** Keys are compared without trimming, case folding or
  numeric conversion, so `0001` and `1` are different items. Integer keys
  compare by their decimal text.
- **Time needs an offset.** Every timestamp must be ISO-8601 with an explicit
  UTC offset. A naive time is never assumed to be local; it gives
  `due_unknown` or `completion_time_unusable`. The evaluation instant comes
  from `--as-of`, or by default from the target snapshot's `observed_at`.

## Contract (`sesslint.outcome-contract/v1`)

A contract is data. Nothing in it is executed. Unknown keys, condition types
and operators are rejected, so a typo can never weaken a check.

```json
{
  "schema_version": "sesslint.outcome-contract/v1",
  "name": "orders-to-shipments",
  "version": "1",
  "key": {"source": "order_id", "target": "order_ref"},
  "eligibility": [{"field": "state", "op": "ne", "value": "cancelled"}],
  "due": {"source_time_field": "placed_at", "within_seconds": 3600},
  "conditions": [
    {"id": "shipment-exists", "type": "exists"},
    {"id": "single-shipment", "type": "count", "min": 1, "max": 1},
    {"id": "status-known", "type": "one_of", "field": "status",
     "values": ["shipped", "delivered"], "normalize": ["trim", "casefold"]},
    {"id": "shipped-on-time", "type": "on_time", "basis": "target_time", "field": "shipped_at"}
  ]
}
```

- `key.source` and `key.target` each take one field name or a list of up to 8
  field names. Use a list for composite keys, for example a tenant and an id.
- `eligibility` is a list of predicates on the source record that must all
  hold:
  - An item that fails one is `NOT_APPLICABLE`.
  - An item whose field is missing or cannot be compared is `INCONCLUSIVE`.
  - `present` and `absent` treat null and an empty string, list or object as
    absent. On a field that occurs in no source record they are undecidable
    (`INCONCLUSIVE`), so a renamed or misspelled field never reads as absent.
    Route `when` predicates follow the same rules (`route_undecidable`).
  - Operators: `eq`, `ne`, `in`, `not_in`, `gt`, `gte`, `lt`, `lte`,
    `present`, `absent`.
- `due` sets the deadline to the source time field plus `within_seconds`.
  Before the deadline, missing results are `PENDING`.
- Each condition takes an `id`, plus two optional flags:
  - `"advisory": true` reports the condition but does not decide the outcome.
  - `"disabled": "<reason>"` skips the condition and records why.

| Type | Checks |
| --- | --- |
| `exists` | At least one matching target record exists. |
| `count` | Between `min` and `max` matching records exist. `min` defaults to 1. Both are integers from 0 to 1,000,000, the snapshot record cap; `null` is rejected. `max: 0` is rejected because v1 cannot prove absence. |
| `required` | The target field is present, non-null and non-empty. An empty string, list or object is empty. `allow_null` and `allow_empty` relax this. |
| `type` | When present, the field has the declared `kind`: `string`, `integer`, `number`, `boolean` or `date-time`. |
| `one_of` | When present, the field is in `values`, after the optional `normalize` steps (`trim`, `casefold`). `values` cannot hold `null`, because a null field is `value_absent` and never matches. |
| `equals` | The target `field` equals the source `source_field`, after normalization. |
| `range` | When present, the field is a number between `min` and `max`. |
| `route` | When every `when` predicate holds on the source, the target field is in `values`. Routing is judged separately from existence. `values` cannot hold `null`, because a null field is `wrong_route` and never matches. |
| `on_time` | Needs `due`. `basis: "target_time"` checks that a completion time in `field` is at or before the deadline; only times from the source event up to the target observation count. `basis: "observation"` accepts a record visible in a snapshot taken at or before the deadline and not before the source event. |
| `any_of` | At least one of two or more branch conditions verifies. Branches cannot contain another `any_of`. |

`equals` compares values as text. The exception is a JSON number on either
side, which compares numerically and exactly: CSV `12.50` equals JSON `12.5` and
CSV `0.1` equals JSON `0.1`, but CSV `0012` does not equal the JSON string
`"12"`.

The `eq`, `ne`, `in` and `not_in` predicates (in `eligibility` and route `when`)
and the `values` of `one_of` and `route` follow the same rule. A contract
number matches a record value by exact value when that value reads as a number:
a JSON number, or CSV text that counts as a number (see below). So CSV `12.50`
matches `12.5` and CSV `0012` matches `12`, but CSV `9007199254740993` does not
match `9007199254740992`. Any other value compares as text, and a contract
string always compares as text, so CSV `0012` does not match `"12"`.
Normalization (`trim`, `casefold`) applies only to the text comparison. Keys
still match exactly as text.

One exception fails closed. CSV text that looks like a number but does not
count as one (a leading or trailing space as in ` 12`, more than 100
characters, or an exponent with more than 6 digits) cannot be decided against
a contract whose values include a number, unless it matches a contract value
as text. Unequal text would prove nothing, so such a value is `INCONCLUSIVE`:
`eligibility_undecidable` in `eligibility`, `route_undecidable` in a route
`when`, and `value_undecidable` for the `values` of `one_of` and `route`.

CSV values are untyped text and are coerced strictly. A CSV number is plain
ASCII decimal text of at most 100 characters: an optional sign, digits, an
optional fraction and an optional exponent whose value has at most 6 digits.
So the CSV value `5` counts as a number, but `1_000`, non-ASCII digits or a
400-digit value do not. The same rule decides `type`, `range`, the numeric
predicates and the number matching above. JSON values keep their types, so the
JSON string `"5"` is not a number.

Run `sesslint outcome contract.json --explain` to print exactly what a contract
checks before you rely on it. `--explain` prints plain text only; combining it
with `--json` or `--format json` is a usage error (exit `2`), and a
`SESSLINT_FORMAT=json` default does not apply to it.

## Snapshots (`sesslint.snapshot/v1`)

A snapshot can be any of these files:

- a `.csv` file with a header row
- a `.json` array of objects
- a `.jsonl` or `.ndjson` file
- a `.json` envelope, shown below

```json
{
  "schema_version": "sesslint.snapshot/v1",
  "observed_at": "2026-10-20T12:00:00Z",
  "completeness": "complete",
  "origin": "target_system",
  "demo": false,
  "records": [{"order_ref": "0001", "status": "shipped"}]
}
```

| Field | Values | Default |
| --- | --- | --- |
| `completeness` | `complete`, `partial`, `unknown`, `unavailable` | `unknown` |
| `origin` | `target_system`, `workflow_log`, `user_file`, `manual` | `user_file` |

A plain file cannot carry this metadata. Supply it with flags such as
`--target-completeness`. If a flag contradicts the envelope, the command fails
with an error. Snapshot size is capped by `--max-file-bytes`, and a snapshot can
hold at most 1,000,000 records.

In a `.jsonl` or `.ndjson` file, each record ends at a line feed (`\n`); a
carriage return before it is ignored. Characters such as U+2028 inside a string
never split a record.

## Report (`sesslint.outcome-report/v1`)

The report is content-free. It holds keys, field names, counts, times and
reason codes, never record values.

- **Condition detail.** By default (`condition_detail: "non_passing"`), the
  following condition results are listed:
  - every condition result of each item that is not `VERIFIED` or `NOT_APPLICABLE`
  - only the advisory or disabled results of items that pass

  `condition_summary` counts every result per condition. Pass `--all-conditions`
  to list every result, which makes large reports much bigger.

- **`--hash-keys`** replaces each key with `sha256:` and 16 hex characters. This
  is pseudonymous, not anonymous: short or guessable keys can be recovered by
  trying candidates.
- **`demo: true`** on a snapshot is flagged in every output.

The report shows four dimensions:

| Dimension | Values |
| --- | --- |
| `session_integrity` | `not_linked`, or the result of checking the `--session` file you link. The link is recorded as `user_asserted`. |
| `outcome_verification` | The outcome verdict. |
| `monitoring_health` | `not_configured`. Snapshot evaluation does no live monitoring. |
| `incident_handling` | `not_tracked`. |

Item and outcome statuses rank `VIOLATED` > `INCONCLUSIVE` > `PENDING` >
`VERIFIED` > `NOT_EVALUATED` > `NOT_APPLICABLE`. An advisory condition never
raises an item's status.

The JSON Schemas are
[`sesslint.outcome-contract.v1.json`](https://github.com/HPNChanel/sesslint/blob/main/schemas/sesslint.outcome-contract.v1.json),
[`sesslint.snapshot.v1.json`](https://github.com/HPNChanel/sesslint/blob/main/schemas/sesslint.snapshot.v1.json)
and
[`sesslint.outcome-report.v1.json`](https://github.com/HPNChanel/sesslint/blob/main/schemas/sesslint.outcome-report.v1.json).

## Not in this release

This release does not include:

- live connectors to target systems
- scheduled monitoring
- alerts
- incident tracking

OutcomeGuard evaluates the snapshots you export. It does not determine who or
what produced a record, and it does not prove exactly-once side effects.

## Reason codes

Every verdict carries one of these stable codes.

### Existence and count

| Code | Meaning |
| --- | --- |
| `present` | A matching target record was observed. |
| `count_within` | The matched record count is within bounds in a complete snapshot. |
| `missing` | No matching target record in a complete snapshot observed at or after the deadline. |
| `too_few` | Fewer matching records than required in a complete snapshot observed at or after the deadline. |
| `too_many` | More matching records than allowed in a complete snapshot. |
| `duplicates_unconfirmed` | More matching records than allowed were seen, but the snapshot is not declared complete, so paging artifacts cannot be excluded. |
| `upper_bound_unproven` | Enough records were seen, but only a complete snapshot can show there are no extra ones. |

### Deadline and observation

| Code | Meaning |
| --- | --- |
| `awaiting_due` | The deadline has not passed at the evaluation instant. |
| `due_unknown` | The source event time is absent or has no UTC offset, so the deadline is unknown. |
| `target_unavailable` | The target observation is marked unavailable. |
| `target_incomplete` | The target snapshot is not declared complete, so absence cannot be proven. |
| `target_stale` | The target snapshot was observed before the deadline. |
| `target_observed_at_unknown` | The target snapshot has no observation time. |
| `target_unkeyed_rows` | Some target rows have no usable key, so a missing or extra record may be hidden behind a broken mapping. |
| `no_target_record` | No matched target record to inspect. |

### Field checks

| Code | Meaning |
| --- | --- |
| `field_not_in_snapshot` | The field does not occur anywhere in the snapshot (mapping changed?). |
| `field_present` | The field holds an accepted value. |
| `field_absent` | The field is absent from the matched record. |
| `field_null` | The field is null. |
| `field_empty` | The field is an empty string, list or object. |
| `value_absent` | The optional value is absent or null; pair with a required condition to demand it. |
| `value_nested` | The value is nested and cannot be compared. |
| `value_undecidable` | The text looks like a number but does not read as one exactly (surrounding whitespace, over 100 characters or an exponent over 6 digits), so it cannot be matched against the contract's numbers. |
| `type_ok` | The value has the declared kind. |
| `type_mismatch` | The value does not have the declared kind. |
| `value_allowed` | The value is in the allowed set. |
| `value_not_allowed` | The value is not in the allowed set. |
| `in_range` | The value is within the declared bounds. |
| `out_of_range` | The value is outside the declared bounds. |
| `not_a_number` | The value is not a number. |
| `values_match` | Source and target values match after the declared normalization. |
| `values_differ` | Source and target values differ after the declared normalization. |
| `source_value_absent` | The source value is absent, null or nested. |
| `target_value_absent` | The target value is absent or null. |

### Routes

| Code | Meaning |
| --- | --- |
| `route_not_applicable` | The route predicate is false for this item. |
| `route_undecidable` | A route predicate field is absent or not comparable. |
| `route_ok` | The record is on the declared route. |
| `wrong_route` | The record exists but is not on the declared route. |

### Timeliness

| Code | Meaning |
| --- | --- |
| `completed_on_time` | A target completion time between the source event and the observation is at or before the deadline. |
| `late` | The deadline has passed and every target completion time is after it. |
| `completion_before_event` | The completion time, or the snapshot showing the record, is before the source event time, so it cannot be this item's result. |
| `completion_after_observation` | The completion time is after the evaluation instant or the target observation time, so it was not observed and cannot be judged. |
| `late_unconfirmed` | The visible completion is late, but an earlier record may be missing from an incomplete snapshot. |
| `not_completed_by_deadline` | No matching record in a complete snapshot observed at or after the deadline. |
| `completion_time_unusable` | The target completion time is absent or has no UTC offset. |
| `observed_on_time` | The record was visible in a snapshot taken at or before the deadline. |
| `first_seen_after_deadline` | The record was first supplied in a snapshot taken after the deadline; earlier visibility is unknown. |

### Condition control and any_of

| Code | Meaning |
| --- | --- |
| `disabled` | The condition is disabled in the contract. |
| `any_branch_verified` | At least one branch is verified. |
| `all_branches_violated` | Every applicable branch is violated. |
| `branches_undecided` | No branch is verified and at least one could not be decided. |
| `branches_pending` | No branch is verified and at least one is still within its deadline. |
| `branches_not_applicable` | No branch applies to this item. |

### Item verdicts

| Code | Meaning |
| --- | --- |
| `conditions_verified` | Every decisive condition is verified. |
| `condition_violated` | At least one decisive condition is violated. |
| `condition_inconclusive` | At least one decisive condition could not be decided. |
| `condition_pending` | At least one decisive condition is still within its deadline. |
| `conditions_not_applicable` | No decisive condition applies to this item. |
| `conditions_not_evaluated` | No decisive condition could be evaluated. |
| `conditions_partly_evaluated` | The evaluated conditions are verified, but at least one decisive condition could not be evaluated. |
| `key_missing` | The source record has no value for a key field. |
| `key_invalid` | A key value is not a non-empty string or integer. |
| `source_conflict` | Source rows sharing this key disagree on contract-relevant fields. |
| `not_eligible` | An eligibility predicate is false; excluded by the contract. |
| `eligibility_undecidable` | An eligibility field is absent or not comparable. |

### Report outcome

| Code | Meaning |
| --- | --- |
| `source_unavailable` | The source observation is marked unavailable. |
| `source_coverage_unproven` | The source snapshot is not declared complete, so items it does not list were not evaluated. |
| `source_key_field_absent` | A source key field occurs nowhere in the source snapshot. |
| `target_key_field_absent` | A target key field occurs nowhere in the target snapshot. |
| `no_source_items` | The source snapshot lists no work items. |
| `some_items_violated` | At least one item is violated. |
| `some_items_inconclusive` | At least one item could not be decided. |
| `some_items_pending` | At least one item is still within its deadline. |
| `all_items_verified` | Every applicable item is verified. |
| `all_items_not_applicable` | Every item is excluded by eligibility. |
| `items_not_evaluated` | No item could be evaluated. |
| `some_items_not_evaluated` | The other items are verified, but at least one item could not be evaluated. |
