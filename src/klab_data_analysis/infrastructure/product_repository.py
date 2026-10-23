import asyncpg

from ..models import Product, Vulnerability


class ProductRepository:
    """Предоставляет сервисам доступ к данным о продуктах и уязвимостях."""

    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def find_products_by_name(self, product_name: str) -> list[Product]:
        """Найти продукты с точным названием; у разных производителей оно может совпадать."""
        async with self._pool.acquire() as connection:
            rows = await connection.fetch(
                """
                SELECT id, vendor, name
                FROM products
                WHERE name = $1
                ORDER BY vendor
                """,
                product_name,
            )
        return [Product(id=row["id"], vendor=row["vendor"], name=row["name"]) for row in rows]

    async def get_versions_for_product(self, product_id: int) -> list[str]:
        """Вернуть все известные версии продукта."""
        async with self._pool.acquire() as connection:
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
        self,
        product_id: int,
    ) -> list[Vulnerability]:
        """Вернуть все записи об уязвимостях продукта."""
        async with self._pool.acquire() as connection:
            rows = await connection.fetch(
                """
                SELECT kla_id, description, publish_date,
                       start_vuln_version, fixed_version
                FROM vulnerabilities
                WHERE product_id = $1
                ORDER BY publish_date DESC, kla_id
                """,
                product_id,
            )
        return [
            Vulnerability(
                kla_id=row["kla_id"],
                description=row["description"],
                publish_date=row["publish_date"],
                start_vuln_version=row["start_vuln_version"],
                fixed_version=row["fixed_version"],
            )
            for row in rows
        ]
