from ..models import Product, Vulnerability
from .ports.product_repository import ProductRepositoryPort


def _version_key(version: str) -> tuple[int, ...]:
    """Преобразовать числовую версию с точками в ключ для сравнения."""
    parts = [int(part) for part in version.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


class ProductService:
    """Содержит логику поиска версий и уязвимостей продукта."""

    def __init__(self, repository: ProductRepositoryPort) -> None:
        self._repository = repository

    async def find_products_by_name(self, product_name: str) -> list[Product]:
        """Найти продукты по точному названию."""
        return await self._repository.find_products_by_name(product_name)

    async def get_safe_version(self, product_id: int) -> str | None:
        """Выбрать наибольшую известную версию без известных уязвимостей."""
        versions = await self._repository.get_versions_for_product(product_id)
        if not versions:
            return None

        vulnerabilities = await self._repository.get_vulnerabilities_for_product(
            product_id
        )

        safe_versions = []
        for version in versions:
            version_number = _version_key(version)
            is_vulnerable = any(
                _version_key(row.start_vuln_version)
                <= version_number
                < _version_key(row.fixed_version)
                for row in vulnerabilities
            )
            if not is_vulnerable:
                safe_versions.append(version)

        if not safe_versions:
            return None
        return max(safe_versions, key=_version_key)

    async def get_vulnerabilities_for_version(
        self,
        product_id: int,
        version: str,
    ) -> list[Vulnerability]:
        """Вернуть уязвимости, диапазон которых включает заданную версию."""
        version_number = _version_key(version)
        vulnerabilities = await self._repository.get_vulnerabilities_for_product(
            product_id
        )

        return [
            row
            for row in vulnerabilities
            if _version_key(row.start_vuln_version)
            <= version_number
            < _version_key(row.fixed_version)
        ]
