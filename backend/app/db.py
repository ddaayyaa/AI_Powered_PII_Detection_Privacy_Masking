import os, uuid
from datetime import datetime, timezone
from sqlalchemy import create_engine, String, Integer, Float, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, relationship

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./pii.db")
if DATABASE_URL.startswith("postgresql+psycopg2://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql+psycopg2://", "postgresql+psycopg://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
Session = sessionmaker(engine, expire_on_commit=False)
now = lambda: datetime.now(timezone.utc)
uid = lambda p: f"{p}_{uuid.uuid4().hex[:10]}"

class Base(DeclarativeBase): pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: uid("usr"))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(10), default="ANALYST")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class Document(Base):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: uid("doc"))
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    filename: Mapped[str] = mapped_column(String(255), index=True)
    size: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20), default="completed", index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    risk_level: Mapped[str] = mapped_column(String(10), default="LOW", index=True)
    strategy: Mapped[str] = mapped_column(String(12), default="FULL")
    output_name: Mapped[str] = mapped_column(String(64), nullable=True)  # random temp filename
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    entities = relationship("PIIEntity", cascade="all, delete-orphan")

class TextScan(Base):
    __tablename__ = "text_scans"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: uid("scan"))
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    input_text: Mapped[str] = mapped_column(Text)
    masked_text: Mapped[str] = mapped_column(Text)
    entities: Mapped[list] = mapped_column(JSON)
    risk_score: Mapped[float] = mapped_column(Float, default=0)
    risk_level: Mapped[str] = mapped_column(String(10), default="LOW", index=True)
    strategy: Mapped[str] = mapped_column(String(12), default="FULL")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)

class PIIEntity(Base):  # metadata only: raw PII is never stored
    __tablename__ = "pii_entities"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: uid("ent"))
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.id"), index=True)
    type: Mapped[str] = mapped_column(String(32), index=True)
    start: Mapped[int] = mapped_column(Integer); end: Mapped[int] = mapped_column(Integer)
    confidence: Mapped[float] = mapped_column(Float)
    method: Mapped[str] = mapped_column(String(10)); risk: Mapped[str] = mapped_column(String(8), index=True)
    status: Mapped[str] = mapped_column(String(12), default="detected")

class AuditLog(Base):  # privacy-preserving: counts and ids only
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    user_id: Mapped[str] = mapped_column(String(32)); document_id: Mapped[str] = mapped_column(String(32), nullable=True)
    action: Mapped[str] = mapped_column(String(30)); detected: Mapped[int] = mapped_column(Integer, default=0)
    masked: Mapped[int] = mapped_column(Integer, default=0); risk_level: Mapped[str] = mapped_column(String(10), default="LOW")
    status: Mapped[str] = mapped_column(String(15), default="ok")
