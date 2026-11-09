import copy
import itertools
import json
import random
import sys
import types
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "outcome.engine"))
import part03


def raw(v):
    return json.dumps(v, ensure_ascii=True, allow_nan=False)


def tag(v):
    return part03.tag(v)


cases = []


def add(op, **kw):
    cases.append(dict(op=op, **kw))


keys = [
    "",
    "a",
    " A ",
    "Straße",
    "é",
    "e\u0301",
    "\U0001f680",
    "\ue000",
    "\U00010000",
    "\x00\n\r\t\b\f\x7f",
    '"\\/',
    "001",
    "1",
]
for n in range(3):
    for key in itertools.product(keys, repeat=n):
        add("hash", key=key)
values = [
    None,
    False,
    True,
    0,
    1,
    -1,
    10**400,
    -(10**400),
    0.0,
    -0.0,
    1e-7,
    1e20,
    1.7976931348623157e308,
    5e-324,
    *keys,
    [],
    {},
    [None, 1, {}],
    {"z": 1, "a": [False, "é", -0.0]},
]
for val, pretty in itertools.product(values, [False, True]):
    add("json", raw=raw(val), pretty=pretty)
for value, op in itertools.product(
    values[:-4], ["present", "absent", "eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "bad"]
):
    if type(value) in (list, dict):
        continue
    add("predicate", raw=raw(dict(field="f-é", op=op, value=value, values=[None, True, "é", 1.5])))
for linked, limit, error, assurance, total, fingerprint in itertools.product(
    [False, True],
    [None, 0, -1, 1, 104857601],
    [None, "os", "value"],
    ["A0", "A1", "A2"],
    [0, 2],
    [None, "f" * 64],
):
    add(
        "session",
        linked=linked,
        limit=limit,
        error=error,
        assurance=assurance,
        total=total,
        fingerprint=fingerprint,
    )
rng = random.Random(4001)
available = [c for c in part03.cases if c["op"] == "evaluate"]
selected = rng.sample(available, 450) + available[-2:]
# Targeted visible-report limits and Unicode keys, payload markers in unused fields.
selected += [
    dict(
        op="evaluate",
        contract=part03.contract(),
        source=part03.snap([dict(x=f"key-{n:03}", secret="SOURCE-PAYLOAD-xyz") for n in range(55)]),
        target=part03.snap(
            [dict(x=f"other-{n:03}", secret="TARGET-PAYLOAD-xyz") for n in range(1001)]
        ),
        as_of=part03.T[2],
    )
]
for base, hashed, all_conditions in itertools.product(selected, [False, True], [False, True]):
    c = copy.deepcopy(base)
    c.update(op="report", hash=hashed, all=all_conditions, name="synthetic-é🚀")
    c["source"]["demo"] = rng.choice([False, True])
    c["target"]["demo"] = rng.choice([False, True])
    c["session"] = raw(
        rng.choice(
            [
                {},
                dict(status="not_linked"),
                dict(status="unreadable", assurance="A0"),
                dict(status="findings", finding_count=1),
                dict(status=None),
                dict(status=True),
                dict(status=1.5),
            ]
        )
    )
    cases.append(c)


def expected(engine, report):
    e = engine
    r = report
    previous_api = sys.modules.get("sesslint.api")
    from sesslint.outcome.contract import Due

    def record(s):
        return {
            k: v if v is None or type(v) in (str, int, float, bool) else e.NON_SCALAR
            for k, v in json.loads(s).items()
        }

    def snapshot(s, role):
        rows = tuple(record(raw) for raw in s["rows"])
        fields = frozenset(s.get("fields", {k for row in rows for k in row}))
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
            s.get("demo", False),
        )

    def condition(c):
        c = dict(c)
        c["when"] = tuple(e.Predicate(**p) for p in c.get("when", []))
        c["conditions"] = tuple(condition(x) for x in c.get("conditions", []))
        return e.Condition(**c)

    output = []
    for c in cases:
        try:
            op = c["op"]
            if op == "hash":
                out = r._hashed(tuple(c["key"]))
            elif op == "json":
                out = json.dumps(
                    json.loads(c["raw"]),
                    ensure_ascii=True,
                    sort_keys=True,
                    indent=2 if c["pretty"] else None,
                )
            elif op == "predicate":
                out = r._describe_predicate(e.Predicate(**json.loads(c["raw"])))
            elif op == "session":
                called = []

                def check_file(path, *, max_file_bytes, c=c, called=called):
                    called.append(max_file_bytes)
                    if c["error"] == "os":
                        raise OSError("synthetic")
                    if c["error"] == "value":
                        raise ValueError("synthetic")
                    return types.SimpleNamespace(
                        assurance=c["assurance"],
                        counts=types.SimpleNamespace(
                            total=c["total"], by_code={"SL002": 1, "SL001": 1}
                        ),
                        source_fingerprint=c["fingerprint"],
                    )

                sys.modules["sesslint.api"] = types.SimpleNamespace(check_file=check_file)
                out = dict(
                    result=tag(
                        r.session_dimension(
                            Path("synthetic") if c["linked"] else None, max_file_bytes=c["limit"]
                        )
                    ),
                    limit=called[0] if called else None,
                )
            else:
                v = c["contract"]
                con = e.Contract(
                    c["name"],
                    "1",
                    None,
                    tuple(v["source_key"]),
                    tuple(v["target_key"]),
                    tuple(e.Predicate(**p) for p in v["eligibility"]),
                    Due(**v["due"]) if v["due"] else None,
                    tuple(condition(x) for x in v["conditions"]),
                    "0",
                )
                try:
                    ev = e.evaluate(
                        con,
                        snapshot(c["source"], "source"),
                        snapshot(c["target"], "target"),
                        as_of=e.parse_instant(c["as_of"]) or datetime(2026, 11, 9),
                    )
                except e.EvaluationError as error:
                    out = dict(evaluation_error=str(error))
                else:
                    report = r.OutcomeReport(ev, json.loads(c["session"]), c["hash"], c["all"])
                    out = dict(
                        dict=tag(report.to_dict()),
                        json=report.to_json(),
                        human=report.render_human(),
                        outcome=report.outcome,
                        exit=report.exit_code,
                        demo=report.demo,
                        keys=[report._display_key(i) for i in ev.items],
                    )
                    assert all(
                        marker not in out["json"] + out["human"]
                        for marker in ["SOURCE-PAYLOAD-xyz", "TARGET-PAYLOAD-xyz"]
                    )
            output.append(dict(ok=out))
        except KeyError as error:
            output.append(dict(error=str(error)))
    if previous_api is None:
        sys.modules.pop("sesslint.api", None)
    else:
        sys.modules["sesslint.api"] = previous_api
    return output
