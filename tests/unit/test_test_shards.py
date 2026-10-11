from __future__ import annotations

from tests.conftest import shard_of


def test_every_test_lands_in_exactly_one_shard_whatever_the_count():
    nodeids = [f"tests/unit/test_{module}.py::test_{case}[{param}]"
               for module in range(20) for case in range(10) for param in ("a", "b")]
    for count in (1, 2, 3, 4):
        shards = [shard_of(nodeid, count) for nodeid in nodeids]
        assert set(shards) == set(range(1, count + 1))
        assert all(shard == shard_of(nodeid, count) for nodeid, shard in zip(nodeids, shards))
