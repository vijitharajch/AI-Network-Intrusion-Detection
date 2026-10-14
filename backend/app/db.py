from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from .config import DATABASE_URL

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    prediction = Column(String(100), nullable=False)
    confidence = Column(Float, nullable=False)
    anomaly = Column(Integer, default=0)
    risk = Column(String(20), nullable=False)
    source_ip = Column(String(64), default="unknown")
    destination_ip = Column(String(64), default="unknown")
    details = Column(Text, default="")

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
