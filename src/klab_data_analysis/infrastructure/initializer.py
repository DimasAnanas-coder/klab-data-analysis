import asyncio

from ..config.path import PROJECT_ROOT
from .database import connect


async def initialize_database() -> None:
    migration_path = PROJECT_ROOT / "migrations" / "001_initial_schema.sql"
    migration = migration_path.read_text(encoding="utf-8")

    connection = await connect()
    try:
        async with connection.transaction():
            await connection.execute(migration)
    finally:
        await connection.close()


def cli() -> None:
    asyncio.run(initialize_database())
    print("Database tables are ready.")


if __name__ == "__main__":
    cli()
