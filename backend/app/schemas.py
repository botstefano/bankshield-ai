from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Operation = Literal["navigation", "banking_access", "link_review"]


class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    source_app: str = Field(default="", max_length=100)
    operation: Operation = "link_review"
    correlation_id: str = Field(default="", max_length=100)
    context: dict[str, Any] = Field(default_factory=dict)


class BatchRequest(BaseModel):
    items: list[AnalyzeRequest] = Field(min_length=1)


class AnalysisOut(BaseModel):
    id: str
    created_at: datetime
    url: str
    domain: str
    level: str
    score: float
    ml_probability: float | None
    indicators: list[dict]
    evidence: list[dict]
    recommendation: str
    explanation: str
    data_incomplete: bool
    engine_version: str
    model_version: str
    correlation_id: str
    latency_ms: float

    model_config = {"from_attributes": True}


class AlertOut(BaseModel):
    id: int
    analysis_id: str
    level: str
    status: str
    assignee_id: int | None
    note: str
    created_at: datetime
    updated_at: datetime
    url: str | None = None
    domain: str | None = None
    score: float | None = None

    model_config = {"from_attributes": True}


class AlertPatch(BaseModel):
    status: Literal["open", "investigating", "resolved", "false_positive", "confirmed"] | None = None
    assignee_id: int | None = None
    note: str | None = Field(default=None, max_length=2000)


class LoginRequest(BaseModel):
    email: str
    password: str


class UserCreate(BaseModel):
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    full_name: str = ""
    password: str = Field(min_length=10, max_length=128)
    role: Literal["admin", "analyst", "operator", "auditor", "manager"] = "operator"


class UserOut(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    is_active: bool

    model_config = {"from_attributes": True}


class IndicatorIn(BaseModel):
    url: str = Field(max_length=2048)
    source: str = Field(default="manual", max_length=64)
    kind: str = Field(default="phishing", max_length=32)
