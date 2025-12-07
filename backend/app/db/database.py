from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy.pool import NullPool
from sqlalchemy import text
from typing import AsyncGenerator
import asyncio
from functools import wraps

from ..core.config import settings

# Create async engine with SQLite-specific optimizations
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True,
    # SQLite-specific settings for better concurrency
    connect_args={
        "timeout": 30,  # Increase timeout for locked database
        "check_same_thread": False,
    },
    poolclass=NullPool,  # Disable connection pooling for SQLite
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)

# Base class for models
Base = declarative_base()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for getting database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Initialize database tables and configure SQLite for WAL mode."""
    async with engine.begin() as conn:
        # Enable WAL mode for better concurrency
        await conn.execute(text("PRAGMA journal_mode=WAL"))
        # Set busy timeout
        await conn.execute(text("PRAGMA busy_timeout=30000"))  # 30 seconds
        # Create tables
        await conn.run_sync(Base.metadata.create_all)


def with_db_retry(max_retries: int = 3, delay: float = 0.5):
    """Decorator to retry database operations on lock errors."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            from sqlalchemy.exc import OperationalError
            
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except OperationalError as e:
                    if "database is locked" in str(e):
                        last_exception = e
                        if attempt < max_retries - 1:
                            wait_time = delay * (2 ** attempt)  # Exponential backoff
                            print(f"Database locked, retrying in {wait_time}s... (attempt {attempt + 1}/{max_retries})")
                            await asyncio.sleep(wait_time)
                        else:
                            print(f"Database locked after {max_retries} attempts")
                    else:
                        raise
            
            # If we exhausted all retries, raise the last exception
            if last_exception:
                raise last_exception
        
        return wrapper
    return decorator
