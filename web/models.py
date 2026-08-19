"""Pydantic request models for ViperACL API endpoints."""

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from core.projects import (
    validate_project_name,
    validate_dc_ip,
    validate_foothold_username,
    validate_foothold_password,
    validate_domain,
)


class IngestRequest(BaseModel):
    zip_path: str = Field(..., min_length=1)
    project_id: str | None = None
    clear_database: bool = False


class ExecuteIngestRequest(BaseModel):
    staged_path: str = Field(..., min_length=1)
    project_id: str | None = None
    clear_database: bool = True


class SelectProjectRequest(BaseModel):
    project_id: str = Field(..., min_length=1)


class CreateProjectRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=64, description="Unique project assessment name")
    dc_ip: str | None = Field(default="", max_length=128, description="Domain Controller IP or hostname")
    foothold_username: str | None = Field(default="", max_length=64, description="Foothold account without domain prefix")
    foothold_password: str | None = Field(default="", max_length=256, description="Foothold account password")
    zip_path: str | None = None

    @field_validator("name")
    @classmethod
    def check_project_name(cls, v: str) -> str:
        valid, result = validate_project_name(v)
        if not valid:
            raise ValueError(result)
        return result

    @field_validator("dc_ip")
    @classmethod
    def check_dc_ip(cls, v: str | None) -> str:
        valid, result = validate_dc_ip(v)
        if not valid:
            raise ValueError(result)
        return result

    @field_validator("foothold_username")
    @classmethod
    def check_foothold_username(cls, v: str | None) -> str:
        valid, result = validate_foothold_username(v)
        if not valid:
            raise ValueError(result)
        return result

    @field_validator("foothold_password")
    @classmethod
    def check_foothold_password(cls, v: str | None) -> str:
        valid, result = validate_foothold_password(v)
        if not valid:
            raise ValueError(result)
        return result


class UpdateProjectTargetRequest(BaseModel):
    project_id: str | None = None
    dc_ip: str | None = Field(default="", max_length=128)
    foothold_username: str | None = Field(default="", max_length=64)
    foothold_password: str | None = Field(default="", max_length=256)
    domain: str | None = Field(default="", max_length=128)

    @field_validator("dc_ip")
    @classmethod
    def check_dc_ip(cls, v: str | None) -> str:
        valid, result = validate_dc_ip(v)
        if not valid:
            raise ValueError(result)
        return result

    @field_validator("foothold_username")
    @classmethod
    def check_foothold_username(cls, v: str | None) -> str:
        valid, result = validate_foothold_username(v)
        if not valid:
            raise ValueError(result)
        return result

    @field_validator("foothold_password")
    @classmethod
    def check_foothold_password(cls, v: str | None) -> str:
        valid, result = validate_foothold_password(v)
        if not valid:
            raise ValueError(result)
        return result

    @field_validator("domain")
    @classmethod
    def check_domain(cls, v: str | None) -> str:
        valid, result = validate_domain(v)
        if not valid:
            raise ValueError(result)
        return result


class PathfindRequest(BaseModel):
    source_name: str = Field(..., min_length=1)
    target_name: str = Field(..., min_length=1)
    mode: Literal["tactical", "fasttrack", "predictive"] = "tactical"
    project_id: str | None = None


class PrivescPlanRequest(BaseModel):
    path: Any


class RemediationRequest(BaseModel):
    targets: list[dict[str, Any]] = Field(default_factory=list)


class GenerateRemediationRequest(BaseModel):
    targets: list[dict[str, Any]] = Field(..., description="List of selected remediation edge targets")
    all_edges: list[dict[str, Any]] = Field(default_factory=list, description="Full sequence of edges along the attack path")
    path_summary: dict[str, Any] | None = Field(default_factory=dict, description="Contextual path metadata")
    project_id: str | None = None


class TestDatabaseRequest(BaseModel):
    uri: str = Field("bolt://127.0.0.1:7687", min_length=1)
    username: str = Field("neo4j", min_length=1)
    password: str = Field(..., min_length=1)
    database: str = Field("neo4j", min_length=1)


class UnlockPhaseRequest(BaseModel):
    phase: Literal["phase_1", "phase_2", "all"] = "all"
    project_id: str | None = None


class SavePathRequest(BaseModel):
    engine: str = Field(..., min_length=1)
    path: dict[str, Any] = Field(default_factory=dict)
    candidate_paths: list[dict[str, Any]] | None = None
    selected_path_index: int | None = 0
    source_name: str | None = None
    target_name: str | None = None
    unlock_phase: Literal["phase_1", "phase_2", "all"] | None = None
    project_id: str | None = None


class SetActivePhaseRequest(BaseModel):
    phase: Literal["phase_1", "phase_2", "phase_3", "phase_4"] = "phase_1"
    project_id: str | None = None



