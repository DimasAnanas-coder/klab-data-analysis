from datetime import date

import pytest

from klab_data_analysis.application.product_service import ProductService
from klab_data_analysis.models import Vulnerability


def vulnerability(
    start: str,
    fixed: str,
    kla_id: str = "KLA-1",
) -> Vulnerability:
    return Vulnerability(
        kla_id=kla_id,
        description="Test vulnerability",
        publish_date=date(2026, 1, 1),
        start_vuln_version=start,
        fixed_version=fixed,
    )


class MemoryRepository:
    def __init__(
        self,
        versions: list[str],
        vulnerabilities: list[Vulnerability],
    ) -> None:
        self.versions = versions
        self.vulnerabilities = vulnerabilities

    async def find_products_by_name(self, product_name: str) -> list:
        return []

    async def get_versions_for_product(self, product_id: int) -> list[str]:
        return self.versions

    async def get_vulnerabilities_for_product(
        self,
        product_id: int,
    ) -> list[Vulnerability]:
        return self.vulnerabilities


@pytest.mark.parametrize(
    ("version", "expected_ids"),
    [
        ("1.9", []),
        ("2.0", ["KLA-1"]),
        ("2.4.9", ["KLA-1"]),
        ("2.5", []),
    ],
)
async def test_vulnerability_range_includes_start_but_excludes_fix(
    version: str,
    expected_ids: list[str],
) -> None:
    service = ProductService(MemoryRepository([], [vulnerability("2.0", "2.5")]))

    result = await service.get_vulnerabilities_for_version(1, version)

    assert [row.kla_id for row in result] == expected_ids


async def test_safe_version_uses_available_version_above_missing_fix_boundary() -> None:
    service = ProductService(
        MemoryRepository(
            ["4.1"],
            [vulnerability("0", "4.0")],
        )
    )

    assert await service.get_safe_version(1) == "4.1"


async def test_safe_version_excludes_a_version_if_any_range_contains_it() -> None:
    service = ProductService(
        MemoryRepository(
            ["2.0", "2.5", "3.0", "3.2"],
            [
                vulnerability("2.0", "2.5", "KLA-1"),
                vulnerability("3.0", "3.2", "KLA-2"),
            ],
        )
    )

    assert await service.get_safe_version(1) == "3.2"


async def test_safe_version_returns_none_when_every_known_version_is_vulnerable() -> (
    None
):
    service = ProductService(
        MemoryRepository(
            ["2.0", "2.1"],
            [vulnerability("2.0", "2.2")],
        )
    )

    assert await service.get_safe_version(1) is None


async def test_safe_version_returns_none_when_product_has_no_versions() -> None:
    service = ProductService(MemoryRepository([], [vulnerability("1.0", "2.0")]))

    assert await service.get_safe_version(1) is None


async def test_safe_version_uses_numeric_order_when_there_are_no_vulnerabilities() -> (
    None
):
    service = ProductService(MemoryRepository(["3.9", "3.10", "3.8"], []))

    assert await service.get_safe_version(1) == "3.10"


async def test_version_with_trailing_zero_at_fix_boundary_is_safe() -> None:
    service = ProductService(
        MemoryRepository(
            ["2.0", "2.1.0"],
            [vulnerability("2.0", "2.1")],
        )
    )

    assert await service.get_safe_version(1) == "2.1.0"


async def test_invalid_version_input_is_rejected() -> None:
    service = ProductService(MemoryRepository([], []))

    with pytest.raises(ValueError):
        await service.get_vulnerabilities_for_version(1, "2..1")
