import json

import pytest

from klab_data_analysis.infrastructure.importer import (
    import_versions,
    iter_json_rows,
)


class VersionConnection:
    def __init__(self, existing_versions: set[str]) -> None:
        self.existing_versions = existing_versions
        self.calls = 0

    async def fetch(self, query: str, *values: object) -> list[dict[str, int]]:
        self.calls += 1
        pairs = list(zip(values[::2], values[1::2]))
        return [
            {"id": index}
            for index, (_, version) in enumerate(pairs)
            if version not in self.existing_versions
        ]


async def test_import_versions_writes_large_input_in_batches_and_counts_conflicts(
    tmp_path,
) -> None:
    rows = [
        {"vendor": "Vendor", "product": "Product", "version": str(number)}
        for number in range(501)
    ]
    path = tmp_path / "versions.json"
    path.write_text(json.dumps(rows), encoding="utf-8")
    connection = VersionConnection({"1", "500"})

    stats = await import_versions(connection, path, {("Vendor", "Product"): 42})

    assert stats == (499, 2)
    assert connection.calls == 2


def test_iter_json_rows_reads_empty_array(tmp_path) -> None:
    path = tmp_path / "rows.json"
    path.write_text("[]", encoding="utf-8")

    assert list(iter_json_rows(path)) == []


def test_iter_json_rows_preserves_nested_data_and_escaped_characters(tmp_path) -> None:
    rows = [
        {"name": 'comma, bracket ] and quote "', "nested": {"items": [1, 2]}},
        {"name": "second"},
    ]
    path = tmp_path / "rows.json"
    path.write_text(json.dumps(rows), encoding="utf-8")

    assert list(iter_json_rows(path)) == rows


def test_iter_json_rows_rejects_non_array_root(tmp_path) -> None:
    path = tmp_path / "rows.json"
    path.write_text('{"item": {"name": "not an array"}}', encoding="utf-8")

    with pytest.raises(ValueError, match="JSON array"):
        list(iter_json_rows(path))


def test_iter_json_rows_rejects_non_object_rows(tmp_path) -> None:
    path = tmp_path / "rows.json"
    path.write_text('[{"name": "ok"}, 4]', encoding="utf-8")

    with pytest.raises(ValueError, match="JSON objects"):
        list(iter_json_rows(path))
