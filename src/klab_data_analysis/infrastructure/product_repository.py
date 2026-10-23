import asyncpg


async def find_products_by_name(
    connection: asyncpg.Connection,
    product_name: str,
) -> list[asyncpg.Record]:
    """Найти продукты с точным названием; у разных производителей оно может совпадать."""
    return await connection.fetch(
        """
        SELECT id, vendor, name
        FROM products
        WHERE name = $1
        ORDER BY vendor
        """,
        product_name,
    )


async def get_versions_for_product(
    connection: asyncpg.Connection,
    product_id: int,
) -> list[str]:
    """Вернуть все известные версии продукта."""
    rows = await connection.fetch(
        """
        SELECT version
        FROM product_versions
        WHERE product_id = $1
        """,
        product_id,
    )
    return [row["version"] for row in rows]


async def get_vulnerabilities_for_product(
    connection: asyncpg.Connection,
    product_id: int,
) -> list[asyncpg.Record]:
    """Вернуть все записи об уязвимостях продукта."""
    return await connection.fetch(
        """
        SELECT kla_id, description, publish_date,
               start_vuln_version, fixed_version
        FROM vulnerabilities
        WHERE product_id = $1
        ORDER BY publish_date DESC, kla_id
        """,
        product_id,
    )
