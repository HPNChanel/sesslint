import itertools
import json
import random
import struct
from datetime import datetime


def tag(v):
    if v is None:
        return ["null"]
    if type(v) is bool:
        return ["bool", v]
    if type(v) is int:
        return ["int", str(v)]
    if type(v) is float:
        return ["float", struct.pack(">d", v).hex()]
    if type(v) is str:
        return ["str", v]
    if type(v) in (list, tuple):
        return ["array", [tag(x) for x in v]]
    return ["object", {k: tag(x) for k, x in v.items()}]


def raw(v):
    return json.dumps(v, ensure_ascii=True, allow_nan=False)


T = ["2026-11-09T00:00:00Z", "2026-11-09T00:00:01Z", "2026-11-09T00:00:02Z"]


def snap(rows=(), complete="complete", observed=T[1], format="json", **kw):
    return dict(
        rows=[raw(r) for r in rows], complete=complete, observed=observed, format=format, **kw
    )


def contract(**kw):
    return dict(
        dict(
            source_key=["x"],
            target_key=["x"],
            eligibility=[],
            due=None,
            conditions=[dict(id="exists", type="exists")],
        ),
        **kw,
    )


cases = []


def add(**kw):
    cases.append(
        dict(
            dict(op="evaluate", source=snap(), target=snap(), contract=contract(), as_of=T[2]), **kw
        )
    )


values = [
    None,
    False,
    True,
    0,
    1,
    2**53 + 1,
    10**100,
    0.0,
    1.0,
    1.5,
    "",
    "1",
    "true",
    "a",
    " a ",
    "Straße",
    "STRASSE",
    "\U00010000",
    "\ue000",
    [],
    {},
]
records = [{}] + [dict(x=v) for v in values]
for a, b in itertools.product(records, repeat=2):
    for fields in [[], ["x"], ["missing", "x"]]:
        add(op="conflict", source=snap([a, b]), fields=fields)
for source, target, when in itertools.product([None, *T], [None, *T], [None, *T]):
    add(source=snap(observed=source), target=snap(observed=target), as_of=when)
rowsets = [
    [],
    [{}],
    [{"x": True}],
    [{"x": "a"}],
    [{"x": "z"}, {"x": "a"}, {"x": "z"}],
    [{"x": 1}, {"x": "1"}],
    [{"x": "a", "v": None}, {"x": "a", "v": {}}],
    [{"x": "a", "v": 1}, {"x": "a", "v": "1"}],
    [{"x": "\ue000"}, {"x": "\U00010000"}],
]
conditions = [
    dict(id="e", type="exists"),
    dict(id="c", type="count", minimum=0, maximum=1),
    dict(id="r", type="required", field="v"),
    dict(id="eq", type="equals", field="v", source_field="v", normalize=["trim", "casefold"]),
    dict(id="v", type="one_of", field="v", values=["a", "strasse", 1]),
    dict(id="t", type="type", field="v", kind="integer"),
    dict(
        id="route",
        type="route",
        field="v",
        values=["a"],
        when=[dict(field="eligible", op="eq", value=True)],
    ),
    dict(id="range", type="range", field="v", minimum=0, maximum=2),
    dict(id="ot", type="on_time", field="done", basis="target_time"),
    dict(id="oo", type="on_time", basis="observation"),
    dict(id="disabled", type="exists", disabled=""),
    dict(id="advisory", type="exists", advisory=True),
]
conditions += [
    dict(id="any", type="any_of", conditions=conditions[:2]),
    dict(id="empty", type="any_of", conditions=[]),
]
for sr, tr, sc, tc in itertools.product(
    rowsets, rowsets, ["complete", "partial", "unavailable"], ["complete", "unknown"]
):
    add(source=snap(sr, sc), target=snap(tr, tc))
for c, sr, tr in itertools.product(conditions, rowsets, rowsets):
    add(contract=contract(conditions=[c]), source=snap(sr), target=snap(tr))
for start, window in itertools.product(
    [
        None,
        {},
        "bad",
        "2026-11-09T00:00:00",
        "0001-01-01T00:00:00Z",
        "9999-12-31T23:59:59.999999Z",
        *T,
    ],
    [0, 1, 315576000, 2**64 - 1],
):
    add(
        contract=contract(due=dict(source_time_field="start", within_seconds=window)),
        source=snap([dict(x="a", start=start)]),
    )
for conditionset in [
    [],
    [dict(id="x", type="exists", disabled="")],
    [dict(id="x", type="exists", advisory=True)],
]:
    for complete in ["complete", "partial", "unknown", "unavailable"]:
        add(contract=contract(conditions=conditionset), source=snap([{"x": "a"}], complete))
rng = random.Random(3603)


def random_row():
    return {
        k: rng.choice(values + [T[0], T[2]])
        for k in ["x", "v", "eligible", "done", "start"]
        if rng.randrange(4)
    }


for _ in range(6000):
    sr = [random_row() for _ in range(rng.randrange(7))]
    tr = [random_row() for _ in range(rng.randrange(7))]
    if sr and rng.randrange(2):
        sr.append(sr[0].copy())
    preds = rng.choice(
        [
            [],
            [dict(field="eligible", op="present")],
            [dict(field="eligible", op="eq", value=True)],
            [dict(field="v", op="gt", value=0), dict(field="eligible", op="present")],
        ]
    )
    keys = rng.choice([["x"], ["x", "v"], [], ["missing"]])
    c = contract(
        source_key=keys,
        target_key=keys,
        eligibility=preds,
        conditions=rng.sample(conditions, rng.randrange(1, 4)),
        due=rng.choice([None, dict(source_time_field="start", within_seconds=1)]),
    )
    kw = {}
    s = snap(
        sr,
        rng.choice(["complete", "partial", "unknown", "unavailable"]),
        rng.choice([None, *T]),
        rng.choice(["csv", "json"]),
    )
    t = snap(
        tr,
        rng.choice(["complete", "partial", "unknown", "unavailable"]),
        rng.choice([None, *T]),
        rng.choice(["csv", "json"]),
    )
    if rng.randrange(10) == 0:
        s["fields"] = []
    if rng.randrange(10) == 0:
        t["fields"] = []
    add(contract=c, source=s, target=t, as_of=T[2])
# Deliberate duplicate condition ids exercise source insertion order before final sort.
for order in [["z", "a"], ["a", "z"]]:
    branches = [
        dict(
            id="same", type="route", field="v", values=[v], when=[dict(field="x", op="eq", value=k)]
        )
        for k, v in [("z", "first"), ("a", "second")]
    ]
    add(
        contract=contract(conditions=branches),
        source=snap([dict(x=k) for k in order]),
        target=snap([dict(x=k, v=v) for k, v in [("a", "second"), ("z", "first")]]),
    )


def expected(engine):
    global e
    e = engine
    from sesslint.outcome.contract import Due

    def condition(c):
        c = dict(c)
        c["when"] = tuple(e.Predicate(**p) for p in c.get("when", []))
        c["conditions"] = tuple(condition(x) for x in c.get("conditions", []))
        return e.Condition(**c)

    def record(s):
        return {
            k: v if v is None or type(v) in (str, int, float, bool) else e.NON_SCALAR
            for k, v in json.loads(s).items()
        }

    def snapshot(s, role):
        rows = tuple(record(r) for r in s["rows"])
        fields = frozenset(s.get("fields", {k for r in rows for k in r}))
        return e.Snapshot(
            role,
            "synthetic",
            "0",
            s["format"],
            rows,
            fields,
            e.parse_instant(s["observed"]),
            s["complete"],
            "user_file",
            False,
        )

    def item(i):
        return dict(
            key=list(i.key) if i.key is not None else None,
            source_row=i.source_row,
            source_rows=i.source_rows,
            status=i.status,
            reason=i.reason,
            deadline=e.format_instant(i.deadline),
            matched_records=i.matched_records,
            conditions=[tag(c.to_dict()) for c in i.conditions],
            detail=tag(i.detail),
        )

    output = []
    for c in cases:
        s = snapshot(c["source"], "source")
        t = snapshot(c["target"], "target")
        try:
            if c["op"] == "conflict":
                out = e._conflicting(s.records, frozenset(c["fields"]))
            else:
                v = c["contract"]
                con = e.Contract(
                    "probe",
                    "1",
                    None,
                    tuple(v["source_key"]),
                    tuple(v["target_key"]),
                    tuple(e.Predicate(**p) for p in v["eligibility"]),
                    Due(**v["due"]) if v["due"] else None,
                    tuple(condition(x) for x in v["conditions"]),
                    "0",
                )
                result = e.evaluate(
                    con, s, t, as_of=e.parse_instant(c["as_of"]) or datetime(2026, 11, 9)
                )
                out = dict(
                    as_of=e.format_instant(result.as_of),
                    outcome=result.outcome,
                    reasons=list(result.outcome_reasons),
                    items=[item(i) for i in result.items],
                    coverage=tag(result.coverage),
                    unmatched=[list(k) for k in result.unmatched_target_keys],
                )
            output.append(dict(ok=out))
        except e.EvaluationError as error:
            output.append(dict(error=str(error)))
    return output
