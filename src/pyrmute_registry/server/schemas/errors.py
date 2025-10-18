"""Pydantic schemas for error responses."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ErrorDetail(BaseModel):
    """Standard error response."""

    model_config = ConfigDict(
        json_schema_extra={"example": {"detail": "An error occurred"}}
    )

    detail: str = Field(..., description="Error message")


class ValidationErrorDetail(BaseModel):
    """Validation error detail."""

    loc: list[str | int] = Field(..., description="Location of the error")
    msg: str = Field(..., description="Error message")
    type: str = Field(..., description="Error type")


class ValidationErrorResponse(BaseModel):
    """Validation error response with details."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "detail": [
                    {
                        "loc": ["body", "version"],
                        "msg": "field required",
                        "type": "value_error.missing",
                    }
                ],
                "body": {"model_name": "User"},
            }
        }
    )

    detail: list[dict[str, Any]] = Field(..., description="Validation errors")
    body: dict[str, Any] | None = Field(None, description="Request body that failed")


class DatabaseErrorResponse(BaseModel):
    """Database error response."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"detail": "Database error occurred. Please try again later."}
        }
    )

    detail: str = Field(..., description="Error message")


class InternalErrorResponse(BaseModel):
    """Internal server error response."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "detail": "An unexpected error occurred. Please try again later."
            }
        }
    )

    detail: str = Field(..., description="Error message")
