import os
import sys

# Ensure root directory is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import Base


def get_test_engine():
    """Returns a test engine: real PostgreSQL when DATABASE_URL is PG (CI),
    else in-memory SQLite. Spec §15 requires real PG for locking/concurrency;
    CI sets DATABASE_URL to postgres; local defaults to SQLite.
    """
    url = os.getenv("DATABASE_URL", "sqlite:///:memory:")
    if url.startswith("postgresql"):
        # Use a separate test DB is already provided by CI env; create engine directly.
        return create_engine(url)
    return create_engine("sqlite:///:memory:")


@pytest.fixture
def pg_available():
    url = os.getenv("DATABASE_URL", "")
    return url.startswith("postgresql")


@pytest.fixture
def test_engine():
    eng = get_test_engine()
    Base.metadata.create_all(bind=eng)
    try:
        yield eng
    finally:
        Base.metadata.drop_all(bind=eng)
        eng.dispose()


@pytest.fixture
def test_session(test_engine):
    S = sessionmaker(bind=test_engine)
    s = S()
    try:
        yield s
    finally:
        s.close()

