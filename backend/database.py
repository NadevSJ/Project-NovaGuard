"""SQLite database setup — SQLAlchemy models for Users and Investigations."""

from __future__ import annotations

from datetime import datetime
from typing import Generator

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker

DATABASE_URL = "sqlite:///./novaguard.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: int = Column(Integer, primary_key=True, index=True)
    email: str = Column(String(255), unique=True, index=True, nullable=False)
    username: str = Column(String(100), unique=True, index=True, nullable=False)
    password_hash: str = Column(String(255), nullable=False)
    created_at: datetime = Column(DateTime, default=datetime.utcnow, nullable=False)

    investigations = relationship(
        "Investigation", back_populates="user", cascade="all, delete-orphan"
    )


class Investigation(Base):
    __tablename__ = "investigations"

    id: int = Column(Integer, primary_key=True, index=True)
    user_id: int | None = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    input_preview: str = Column(String(200), nullable=False)
    input_type: str = Column(String(20), nullable=False, default="text")
    predicted_label: str = Column(String(20), nullable=False, default="SUSPICIOUS")
    predicted_score: int = Column(Integer, nullable=False, default=50)
    report: str = Column(Text, nullable=True)
    traffic_light: str = Column(String(10), nullable=False, default="yellow")
    recommended_action: str = Column(Text, nullable=True)
    latency_seconds: float = Column(Float, nullable=False, default=0.0)
    created_at: datetime = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="investigations")


def create_tables() -> None:
    """Create all tables if they don't exist."""
    from backend.models.shield import ShieldOrg, ShieldAlert  # noqa: F401 — registers tables
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
