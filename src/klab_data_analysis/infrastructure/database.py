import asyncpg

from ..config.env import database_url


async def connect() -> asyncpg.Connection:
    """Открыть отдельное подключение для одноразовых операций импорта."""
    return await asyncpg.connect(database_url)


async def create_pool() -> asyncpg.Pool:
    """Создать пул подключений к настроенной базе данных."""
    return await asyncpg.create_pool(dsn=database_url)
