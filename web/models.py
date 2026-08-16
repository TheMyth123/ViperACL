"""Pydantic request models for ViperACL API endpoints."""

from typing import Any, Literal

from pydantic import BaseModel, Field


class IngestRequest(BaseModel):
    zip_path: str = Field(..., min_length=1)
    project_id: str | None = None
    clear_database: bool = False


class SelectProjectRequest(BaseModel):
    project_id: str = Field(..., min_length=1)


class CreateProjectRequest(BaseModel):
    name: str = Field(..., min_length=1)
    zip_path: str = Field("dev/20260702105422_VIPERTECH.zip", min_length=1)


class PathfindRequest(BaseModel):
    source_name: str = Field(..., min_length=1)
    target_name: str = Field(..., min_length=1)
    mode: Literal["tactical", "fasttrack", "predictive"] = "tactical"
    project_id: str | None = None


class PrivescPlanRequest(BaseModel):
    path: Any


class RemediationRequest(BaseModel):
    targets: list[dict[str, Any]] = Field(default_factory=list)


class TestDatabaseRequest(BaseModel):
    uri: str = Field("bolt://127.0.0.1:7687", min_length=1)
    username: str = Field("neo4j", min_length=1)
    password: str = Field(..., min_length=1)
    database: str = Field("neo4j", min_length=1)
