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

        # create_all() does not alter tables that already exist. Keep the
        # lightweight SQLite setup self-migrating for installations created
        # before rotating-MAC support was added.
        columns = await conn.execute(text("PRAGMA table_info(devices)"))
        device_columns = {row[1] for row in columns.fetchall()}
        if "mac_aliases" not in device_columns:
            await conn.execute(text("ALTER TABLE devices ADD COLUMN mac_aliases TEXT DEFAULT '[]'"))
        if "discovery_info" not in device_columns:
            await conn.execute(text("ALTER TABLE devices ADD COLUMN discovery_info TEXT"))
        identification_added = "identification" not in device_columns
        if identification_added:
            await conn.execute(text("ALTER TABLE devices ADD COLUMN identification TEXT"))
        if "last_deep_scan_at" not in device_columns:
            await conn.execute(text("ALTER TABLE devices ADD COLUMN last_deep_scan_at DATETIME"))

        # Older releases stored scanner guesses and user overrides in the same
        # column. Lowercase values are the UI's canonical user categories;
        # preserve those and move the legacy display labels into a low-
        # confidence suggestion so future scans cannot overwrite user choices.
        if identification_added:
            canonical_types = (
                "router", "computer", "laptop", "phone", "tablet", "tv",
                "printer", "camera", "speaker", "nas", "server", "iot", "other",
            )
            canonical_sql = ", ".join(f"'{value}'" for value in canonical_types)
            await conn.execute(text(
                "UPDATE devices SET identification = json_object("
                "'version', 1, 'label', device_type, "
                "'category', CASE "
                "WHEN lower(device_type) LIKE '%router%' OR lower(device_type) LIKE '%gateway%' THEN 'router' "
                "WHEN lower(device_type) LIKE '%iphone%' OR lower(device_type) LIKE '%phone%' THEN 'phone' "
                "WHEN lower(device_type) LIKE '%ipad%' OR lower(device_type) LIKE '%tablet%' THEN 'tablet' "
                "WHEN lower(device_type) LIKE '%macbook%' OR lower(device_type) LIKE '%laptop%' THEN 'laptop' "
                "WHEN lower(device_type) LIKE '%printer%' THEN 'printer' "
                "WHEN lower(device_type) LIKE '%camera%' OR lower(device_type) LIKE '%nvr%' THEN 'camera' "
                "WHEN lower(device_type) LIKE '%speaker%' OR lower(device_type) LIKE '%audio%' THEN 'speaker' "
                "WHEN lower(device_type) LIKE '%tv%' OR lower(device_type) LIKE '%cast%' THEN 'tv' "
                "WHEN lower(device_type) LIKE '%nas%' THEN 'nas' "
                "WHEN lower(device_type) LIKE '%server%' THEN 'server' "
                "WHEN lower(device_type) LIKE '%iot%' OR lower(device_type) LIKE '%smart%' THEN 'iot' "
                "ELSE 'other' END, "
                "'confidence', 'low', 'score', 20, "
                "'evidence', json_array(json_object('source', 'legacy', "
                "'summary', 'Classification retained from an earlier scanner version', "
                "'value', device_type, 'strength', 'weak')), "
                "'probes', json_object(), 'identified_at', updated_at) "
                f"WHERE identification IS NULL AND device_type IS NOT NULL AND device_type != '' "
                f"AND device_type NOT IN ({canonical_sql})"
            ))
            await conn.execute(text(
                f"UPDATE devices SET device_type = NULL WHERE identification IS NOT NULL "
                f"AND device_type IS NOT NULL AND device_type NOT IN ({canonical_sql})"
            ))
        await conn.execute(text(
            "UPDATE devices SET model = NULL WHERE model IS NOT NULL "
            "AND model NOT GLOB '*[^0-9,]*' AND instr(model, ',') > 0"
        ))

        # A container restart can interrupt a scan before its normal
        # completion/failure update. Do not let an orphaned "running" row
        # keep the UI's scan indicator stuck forever after startup.
        await conn.execute(text(
            "UPDATE scan_sessions "
            "SET status = 'failed', completed_at = CURRENT_TIMESTAMP, "
            "error_message = COALESCE(error_message, 'Interrupted by backend restart') "
            "WHERE status = 'running'"
        ))


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
