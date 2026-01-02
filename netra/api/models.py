from typing import Optional, Dict, Any
from sqlmodel import Field, SQLModel, JSON, Column
from datetime import datetime


class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    target: str
    scan_type: str = "full"
    status: str = "pending"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    options: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    results: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))
    user_id: Optional[int] = Field(default=None, foreign_key="user.id")


class ScanCreate(SQLModel):
    target: str
    scan_type: str = "full"
    options: Dict[str, Any] = {}


class ScanRead(SQLModel):
    id: int
    target: str
    scan_type: str
    status: str
    created_at: datetime
    results: Dict[str, Any]


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    full_name: Optional[str] = None
    email: Optional[str] = None
    hashed_password: str
    disabled: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    preferences: Dict[str, Any] = Field(default={}, sa_column=Column(JSON))
