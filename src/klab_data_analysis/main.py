import asyncio

from .cli import run_cli
from .application.product_service import ProductService
from .infrastructure.database import create_pool
from .infrastructure.product_repository import ProductRepository


async def _run() -> None:
    pool = await create_pool()
    try:
        repository = ProductRepository(pool)
        service = ProductService(repository)
        await run_cli(service)
    finally:
        await pool.close()


def main() -> None:
    """Запустить консольное приложение."""
    asyncio.run(_run())


if __name__ == "__main__":
    main()
