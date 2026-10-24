import asyncio
from datetime import date
from pathlib import Path
from collections.abc import Iterator
from typing import Any

import asyncpg
import ijson

from ..config.path import VERSIONS_PATH, VULNERABILITIES_PATH
from .database import connect

ProductKey = tuple[str, str]
ImportStats = tuple[int, int]


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

    for vendor, name in sorted(product_keys):
        product_id = await connection.fetchval(
            """
            INSERT INTO products (vendor, name)
            VALUES ($1, $2)
            ON CONFLICT (vendor, name) DO NOTHING
            RETURNING id
            """,
            vendor,
            name,
        )
        if product_id is None:
            existing += 1
            product_id = await connection.fetchval(
                "SELECT id FROM products WHERE vendor = $1 AND name = $2",
                vendor,
                name,
            )
        else:
            inserted += 1
        product_ids[(vendor, name)] = product_id

    return product_ids, (inserted, existing)


async def import_versions(
    connection: asyncpg.Connection,
    versions_path: Path,
    product_ids: dict[ProductKey, int],
) -> ImportStats:
    inserted = 0
    existing = 0

    for row in iter_json_rows(versions_path):
        inserted_id = await connection.fetchval(
            """
            INSERT INTO product_versions (product_id, version)
            VALUES ($1, $2)
            ON CONFLICT (product_id, version) DO NOTHING
            RETURNING id
            """,
            product_ids[(row["vendor"], row["product"])],
            row["version"],
        )
        if inserted_id is None:
            existing += 1
        else:
            inserted += 1

    return inserted, existing


async def import_vulnerabilities(
    connection: asyncpg.Connection,
    vulnerabilities_path: Path,
    product_ids: dict[ProductKey, int],
) -> ImportStats:
    inserted = 0
    existing = 0

    for row in iter_json_rows(vulnerabilities_path):
        inserted_id = await connection.fetchval(
            """
            INSERT INTO vulnerabilities (
                product_id,
                kla_id,
                description,
                publish_date,
                start_vuln_version,
                fixed_version
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (
                product_id,
                kla_id,
                start_vuln_version,
                fixed_version
            ) DO NOTHING
            RETURNING id
            """,
            product_ids[(row["vendor"], row["product"])],
            row["KLA_id"],
            row["description"],
            date.fromisoformat(row["publish_date"]),
            row["start_vuln_version"],
            row["fixed_version"],
        )
        if inserted_id is None:
            existing += 1
        else:
            inserted += 1

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
            version_stats = await import_versions(connection, VERSIONS_PATH, product_ids)
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
