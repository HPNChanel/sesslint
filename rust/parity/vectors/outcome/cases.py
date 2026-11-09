"""Synthetic verify_outcome Cartesian cases (4818 rows)."""

import itertools

SOURCE_NAMES = ["source.json", "source-unicode.json"]
TARGET_NAMES = [
    "target.json",
    "empty.json",
    "unobserved.json",
    "future.json",
    "partial.json",
]
AS_OF_VALUES = [None, "naive", "2026-11-09T00:00:00Z", "2026-11-08T00:00:00Z", "2026-11-11T00:00:00Z"]
SESSION_VALUES = ["none", "ok", "os"]


def build_cases():
    cases = []
    for source, target, loaded, as_of, hash_keys, all_conditions, session in itertools.product(
        SOURCE_NAMES,
        TARGET_NAMES,
        itertools.product([False, True], repeat=3),
        AS_OF_VALUES,
        [False, True],
        [False, True],
        SESSION_VALUES,
    ):
        cases.append(
            dict(
                contract="contract.json",
                source=source,
                target=target,
                loaded=list(loaded),
                as_of=as_of,
                hash_keys=hash_keys,
                all_conditions=all_conditions,
                session=session,
            )
        )
    for invalid_name in ["invalid.json", "missing.json"]:
        for stage in range(3):
            for as_of in [None, "naive", "2026-11-08T00:00:00Z"]:
                paths = ["contract.json", SOURCE_NAMES[0], TARGET_NAMES[0]]
                for k in range(stage, 3):
                    paths[k] = invalid_name
                cases.append(
                    dict(
                        contract=paths[0],
                        source=paths[1],
                        target=paths[2],
                        loaded=[False, False, False],
                        as_of=as_of,
                        hash_keys=False,
                        all_conditions=False,
                        session="ok",
                    )
                )
    assert len(cases) == 4818
    return cases
