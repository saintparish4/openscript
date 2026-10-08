"""The fingerprint an approval is bound to.

An approval is worth what its fingerprint distinguishes. It used to be built
with json.dumps(default=str), and str() forgets what it was given — so these
tests are mostly about pairs of values that look alike and are not.
"""

from __future__ import annotations

import copy
import datetime
import uuid
from decimal import Decimal
from enum import IntEnum
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from events.approvals import action_hash


class Level(IntEnum):
    LOW = 1


def _call(**args: Any) -> str:
    return action_hash("tool_call", {"name": "transfer", "args": args})


@pytest.mark.parametrize(
    ("one", "other"),
    [
        (Decimal("10"), "10"),
        (Decimal("10"), 10),
        (uuid.UUID(int=7), str(uuid.UUID(int=7))),
        (datetime.date(2026, 10, 7), "2026-10-07"),
        (Level.LOW, 1),
        (True, 1),
        (False, 0),
        (1, 1.0),
        (0.0, -0.0),
        (None, "None"),
        (b"ab", "ab"),
        ({1: "x"}, {"1": "x"}),
        ({"a": 1}, [["a", 1]]),
        ([1], [[1]]),
        ("", None),
    ],
)
def test_values_that_only_look_alike_are_told_apart(one: Any, other: Any):
    assert _call(amount=one) != _call(amount=other)


def test_data_shaped_like_the_encoding_does_not_pass_for_what_it_spells():
    """The tags are data too. A caller who writes them out gets no further."""
    assert _call(v=["int", "1"]) != _call(v=1)
    assert _call(v=["list", [["int", "1"]]]) != _call(v=[1])
    assert _call(v=["object", "decimal.Decimal", "10"]) != _call(v=Decimal("10"))


def test_the_same_call_always_has_the_same_fingerprint():
    assert _call(to="alice", amount=10) == _call(amount=10, to="alice")
    assert _call(v={"b": 1, "a": 2}) == _call(v={"a": 2, "b": 1})
    assert _call(v={3, 1, 2}) == _call(v={2, 3, 1})
    assert _call(v=float("nan")) == _call(v=float("nan"))
    # Deliberately one thing: nothing can be done with a tuple that cannot be
    # done with the list of the same items.
    assert _call(v=[1, 2]) == _call(v=(1, 2))


def test_the_action_and_the_tool_name_are_part_of_it():
    args = {"to": "alice", "amount": 10}
    assert action_hash("tool_call", {"name": "a", "args": args}) != action_hash(
        "tool_call", {"name": "b", "args": args}
    )
    assert action_hash("tool_call", {"name": "a", "args": args}) != action_hash(
        "invoke", {"name": "a", "args": args}
    )


# ---------------------------------------------------------------------------
# The same claim for values nobody listed: two inputs share a fingerprint
# exactly when they are the same values of the same types.
# ---------------------------------------------------------------------------

_leaf = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-5, max_value=5),
    st.sampled_from([0.0, -0.0, 1.0, 2.5, float("inf"), float("nan")]),
    st.sampled_from(["", "1", "1.0", "True", "None", "a", "10"]),
    st.sampled_from([Decimal("1"), Decimal("10"), Decimal("1.0")]),
    st.sampled_from([Level.LOW, uuid.UUID(int=1), datetime.date(2026, 1, 1), b"1", b""]),
)
_key = st.one_of(st.sampled_from(["", "1", "a", "True"]), st.integers(0, 2), st.booleans())
_value = st.recursive(
    _leaf,
    lambda inner: st.one_of(
        st.lists(inner, max_size=3),
        st.lists(inner, max_size=3).map(tuple),
        st.dictionaries(_key, inner, max_size=3),
    ),
    max_leaves=6,
)
# Independent draws rarely coincide, so half the pairs are a value and a copy.
_pair = st.one_of(st.tuples(_value, _value), _value.map(lambda v: (v, copy.deepcopy(v))))

_PLAIN = (bool, int, str, bytes, type(None))


def _same(a: Any, b: Any) -> bool:
    """What "the same call" means, written without reference to the encoding."""
    if type(a) in (list, tuple) and type(b) in (list, tuple):
        return len(a) == len(b) and all(map(_same, a, b))
    if type(a) is not type(b):
        return False
    if type(a) is dict:
        return len(a) == len(b) and all(
            any(_same(ka, kb) and _same(va, vb) for kb, vb in b.items()) for ka, va in a.items()
        )
    if type(a) in _PLAIN:
        return bool(a == b)
    # Floats by how they are written (so NaN is itself and -0.0 is not 0.0);
    # anything else by its text, its type already being equal.
    return repr(a) == repr(b) if type(a) is float else str(a) == str(b)


@settings(max_examples=600, deadline=None)
@given(pair=_pair)
def test_fingerprints_match_exactly_when_the_inputs_are_the_same(pair: tuple[Any, Any]):
    one, other = pair
    assert (_call(v=one) == _call(v=other)) is _same(one, other)
