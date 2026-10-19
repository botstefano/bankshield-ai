import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(255), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="operator")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Analysis(Base):
    __tablename__ = "analyses"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    url: Mapped[str] = mapped_column(String(2048))  # sin query ni fragmento (privacidad)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    source_app: Mapped[str] = mapped_column(String(100), default="")
    operation: Mapped[str] = mapped_column(String(32), default="link_review")
    correlation_id: Mapped[str] = mapped_column(String(100), default="")
    level: Mapped[str] = mapped_column(String(32), index=True)
    score: Mapped[float] = mapped_column(Float)
    ml_probability: Mapped[float | None] = mapped_column(Float, nullable=True)
    indicators: Mapped[list] = mapped_column(JSON, default=list)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    recommendation: Mapped[str] = mapped_column(Text, default="")
    explanation: Mapped[str] = mapped_column(Text, default="")
    data_incomplete: Mapped[bool] = mapped_column(Boolean, default=False)
    engine_version: Mapped[str] = mapped_column(String(32))
    model_version: Mapped[str] = mapped_column(String(64), default="")
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[str] = mapped_column(ForeignKey("analyses.id"), index=True)
    level: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, onupdate=now)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    user_email: Mapped[str] = mapped_column(String(255), default="")
    action: Mapped[str] = mapped_column(String(64), index=True)
    resource: Mapped[str] = mapped_column(String(255), default="")
    outcome: Mapped[str] = mapped_column(String(16), default="ok")
    ip: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[str] = mapped_column(Text, default="")


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    __table_args__ = (UniqueConstraint("url_norm", "source", name="uq_indicator"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    url_norm: Mapped[str] = mapped_column(String(2048))
    host: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(32), default="phishing")
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
