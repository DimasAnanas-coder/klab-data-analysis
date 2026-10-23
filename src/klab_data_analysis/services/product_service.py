import asyncpg

from ..infrastructure.product_repository import (
    get_versions_for_product,
    get_vulnerabilities_for_product,
)


def _version_key(version: str) -> tuple[int, ...]:
    """Преобразовать числовую версию с точками в ключ для сравнения."""
    parts = [int(part) for part in version.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


async def get_safe_version(
    connection: asyncpg.Connection,
    product_id: int,
) -> str | None:
    """Выбрать наибольшую исправленную версию или последнюю версию из фида."""
    vulnerabilities = await get_vulnerabilities_for_product(connection, product_id)
    fixed_versions = [
        row["fixed_version"]
        for row in vulnerabilities
        if row["fixed_version"]
    ]
    if fixed_versions:
        return max(fixed_versions, key=_version_key)

    versions = await get_versions_for_product(connection, product_id)
    if not versions:
        return None
    return max(versions, key=_version_key)


async def get_vulnerabilities_for_version(
    connection: asyncpg.Connection,
    product_id: int,
    version: str,
) -> list[asyncpg.Record]:
    """Вернуть уязвимости, диапазон которых включает заданную версию."""
    version_number = _version_key(version)
    vulnerabilities = await get_vulnerabilities_for_product(connection, product_id)

    return [
        row
        for row in vulnerabilities
        if _version_key(row["start_vuln_version"])
        <= version_number
        < _version_key(row["fixed_version"])
    ]
