from typing import Protocol

from ...models import Product, Vulnerability


class ProductRepositoryPort(Protocol):
    """Описывает методы репозитория, необходимые сервису продуктов."""

    async def find_products_by_name(self, product_name: str) -> list[Product]: ...

    async def get_versions_for_product(self, product_id: int) -> list[str]: ...

    async def get_vulnerabilities_for_product(
        self,
        product_id: int,
    ) -> list[Vulnerability]: ...
