import asyncio
import json
from datetime import date
from pathlib import Path
from typing import Any

from ..config.path import VERSIONS_PATH, VULNERABILITIES_PATH
from .database import connect


def load_json(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as file:
        rows = json.load(file)
    if not isinstance(rows, list):
        raise ValueError(f"Expected a JSON array in {path}")
    return rows


async def import_data() -> tuple[int, int]:
    vulnerabilities = load_json(VULNERABILITIES_PATH)
    versions = load_json(VERSIONS_PATH)

    product_keys = {
        (row["vendor"], row["product"])
        for row in [*vulnerabilities, *versions]
    }

    connection = await connect()
    try:
        async with connection.transaction():
            await connection.executemany(
                """
                INSERT INTO products (vendor, name)
                VALUES ($1, $2)
                ON CONFLICT (vendor, name) DO NOTHING
                """,
                sorted(product_keys),
            )

            products = {}
            for vendor, name in product_keys:
                product_id = await connection.fetchval(
                    "SELECT id FROM products WHERE vendor = $1 AND name = $2",
                    vendor,
                    name,
                )
                products[(vendor, name)] = product_id

            await connection.executemany(
                """
                INSERT INTO product_versions (product_id, version)
                VALUES ($1, $2)
                ON CONFLICT (product_id, version) DO NOTHING
                """,
                [
                    (products[(row["vendor"], row["product"])], row["version"])
                    for row in versions
                ],
            )

            await connection.executemany(
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
                """,
                [
                    (
                        products[(row["vendor"], row["product"])],
                        row["KLA_id"],
                        row["description"],
                        date.fromisoformat(row["publish_date"]),
                        row["start_vuln_version"],
                        row["fixed_version"],
                    )
                    for row in vulnerabilities
                ],
            )
    finally:
        await connection.close()

    return len(versions), len(vulnerabilities)


async def main() -> None:
    version_count, vulnerability_count = await import_data()
    print(
        "Import complete: "
        f"processed {version_count} product versions and "
        f"{vulnerability_count} vulnerability records."
    )


def cli() -> None:
    asyncio.run(main())


if __name__ == "__main__":
    cli()
