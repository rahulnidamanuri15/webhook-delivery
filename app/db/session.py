from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

connect_args = {}
engine_kwargs = {
    "pool_pre_ping": True,
    "echo": False,
}

if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False
else:
    # PostgreSQL connection pool: kept small per process because web + worker
    # (x concurrency) + beat + dispatcher each create their own engine.
    # 5 + 5 overflow = 10 per process; 4 processes ≈ 40 < default max_connections=100.
    engine_kwargs.update(
        {
            "pool_size": 5,
            "max_overflow": 5,
            "pool_timeout": 30,
            "pool_recycle": 1800,
        }
    )

engine = create_engine(settings.DATABASE_URL, connect_args=connect_args, **engine_kwargs)

# Per-connection timeouts via SET (not startup options — Neon pooler rejects
# `options` with statement_timeout). Best-effort: failures fall back to defaults.
if not settings.DATABASE_URL.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def set_pg_timeouts(dbapi_connection, connection_record):
        try:
            cur = dbapi_connection.cursor()
            try:
                cur.execute("SET statement_timeout = '15s'")
                cur.execute("SET idle_in_transaction_session_timeout = '30s'")
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
        except Exception:
            pass

# Enable foreign keys + busy timeout + WAL for SQLite (reduces
# "database is locked" under in-process dispatcher threads).
if settings.DATABASE_URL.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
