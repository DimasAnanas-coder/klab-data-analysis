import asyncpg

from ..config.env import database_url


async def connect() -> asyncpg.Connection:
    """Open a connection to the configured PostgreSQL database."""
    return await asyncpg.connect(database_url)
