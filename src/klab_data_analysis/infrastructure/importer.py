import asyncio
from collections.abc import Iterator
from datetime import date
from pathlib import Path
from itertools import islice
from typing import Any

import asyncpg
import ijson

from ..config.path import VERSIONS_PATH, VULNERABILITIES_PATH
from .database import connect

ProductKey = tuple[str, str]
ImportStats = tuple[int, int]
BATCH_SIZE = 500


def batches(items: Iterator[Any], size: int = BATCH_SIZE) -> Iterator[list[Any]]:
    iterator = iter(items)
    while batch := list(islice(iterator, size)):
        yield batch


def values_placeholders(row_count: int, column_count: int) -> str:
    rows = []
    for row in range(row_count):
        start = row * column_count + 1
        end = start + column_count
        rows.append(f"({', '.join(f'${number}' for number in range(start, end))})")
    return ", ".join(rows)


def flatten_rows(rows: list[tuple[Any, ...]]) -> list[Any]:
    return [value for row in rows for value in row]


def iter_json_rows(path: Path) -> Iterator[dict[str, Any]]:
    """Yield objects from a JSON array without reading the whole file at once."""
    with path.open("rb") as file:
        yield from ijson.items(file, "item")


async def import_products(
    connection: asyncpg.Connection,
    product_keys: set[ProductKey],
) -> tuple[dict[ProductKey, int], ImportStats]:
    product_ids = {}
    inserted = 0
    existing = 0

    product_rows = sorted(product_keys)
    for batch in batches(iter(product_rows)):
        placeholders = values_placeholders(len(batch), 2)
        inserted_rows = await connection.fetch(
            f"""
            INSERT INTO products (vendor, name)
            VALUES {placeholders}
            ON CONFLICT (vendor, name) DO NOTHING
            RETURNING vendor, name, id
            """,
            *flatten_rows(batch),
        )
        inserted_keys = set()
        for row in inserted_rows:
            key = (row["vendor"], row["name"])
            inserted_keys.add(key)
            product_ids[key] = row["id"]

        missing_keys = [key for key in batch if key not in inserted_keys]
        if missing_keys:
            placeholders = values_placeholders(len(missing_keys), 2)
            existing_rows = await connection.fetch(
                f"""
                SELECT vendor, name, id
                FROM products
                WHERE (vendor, name) IN (VALUES {placeholders})
                """,
                *flatten_rows(missing_keys),
            )
            for row in existing_rows:
                product_ids[(row["vendor"], row["name"])] = row["id"]

        inserted += len(inserted_rows)
        existing += len(missing_keys)

    return product_ids, (inserted, existing)


async def import_versions(
    connection: asyncpg.Connection,
    versions_path: Path,
    product_ids: dict[ProductKey, int],
) -> ImportStats:
    inserted = 0
    existing = 0

    for batch in batches(iter_json_rows(versions_path)):
        rows = [
            (product_ids[(row["vendor"], row["product"])], row["version"])
            for row in batch
        ]
        placeholders = values_placeholders(len(rows), 2)
        inserted_rows = await connection.fetch(
            f"""
            INSERT INTO product_versions (product_id, version)
            VALUES {placeholders}
            ON CONFLICT (product_id, version) DO NOTHING
            RETURNING id
            """,
            *flatten_rows(rows),
        )
        inserted += len(inserted_rows)
        existing += len(batch) - len(inserted_rows)

    return inserted, existing


async def import_vulnerabilities(
    connection: asyncpg.Connection,
    vulnerabilities_path: Path,
    product_ids: dict[ProductKey, int],
) -> ImportStats:
    inserted = 0
    existing = 0

    for batch in batches(iter_json_rows(vulnerabilities_path)):
        rows = [
            (
                product_ids[(row["vendor"], row["product"])],
                row["KLA_id"],
                row["description"],
                date.fromisoformat(row["publish_date"]),
                row["start_vuln_version"],
                row["fixed_version"],
            )
            for row in batch
        ]
        placeholders = values_placeholders(len(rows), 6)
        inserted_rows = await connection.fetch(
            f"""
            INSERT INTO vulnerabilities (
                product_id,
                kla_id,
                description,
                publish_date,
                start_vuln_version,
                fixed_version
            )
            VALUES {placeholders}
            ON CONFLICT (
                product_id,
                kla_id,
                start_vuln_version,
                fixed_version
            ) DO NOTHING
            RETURNING id
            """,
            *flatten_rows(rows),
        )
        inserted += len(inserted_rows)
        existing += len(batch) - len(inserted_rows)

    return inserted, existing


async def import_data() -> dict[str, ImportStats]:
    product_keys = {
        (row["vendor"], row["product"])
        for path in (VULNERABILITIES_PATH, VERSIONS_PATH)
        for row in iter_json_rows(path)
    }

    connection = await connect()
    try:
        async with connection.transaction():
            product_ids, product_stats = await import_products(connection, product_keys)
            version_stats = await import_versions(
                connection, VERSIONS_PATH, product_ids
            )
            vulnerability_stats = await import_vulnerabilities(
                connection, VULNERABILITIES_PATH, product_ids
            )
    finally:
        await connection.close()

    return {
        "products": product_stats,
        "versions": version_stats,
        "vulnerabilities": vulnerability_stats,
    }


async def main() -> None:
    stats = await import_data()
    print("Import complete:")
    for table, (inserted, existing) in stats.items():
        print(f"  {table}: {inserted} inserted, {existing} already present")


def cli() -> None:
    asyncio.run(main())


if __name__ == "__main__":
    cli()
