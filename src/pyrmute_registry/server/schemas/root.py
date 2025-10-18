"""Pydantic schemas for the root routes."""

from typing import Literal

from pydantic import BaseModel, Field, HttpUrl


class EndpointsResponse(BaseModel):
    """Contains the routes in the API."""

    health: str = Field(..., description="Path to the health route.")
    schemas: str = Field(..., description="Path to the schemas route.")


class DocumentationResponse(BaseModel):
    """Response model for documentation locations."""

    swagger: str | None = Field(None, description="Path to the swagger docs.")
    redoc: str | None = Field(None, description="Path to the redoc docs.")
    openapi: str = Field(..., description="Path to the OpenAPI schema.")


class RootResponse(BaseModel):
    """Response model for the root route."""

    name: str = Field(..., description="Name of the application.")
    version: str = Field(..., description="Version of the application.")
    environment: Literal["development", "production", "test"] = Field(
        ...,
        description=(
            "Current environment the application is running in (dev, test, prod, ...)"
        ),
    )
    documentation: DocumentationResponse = Field(
        ..., description="Paths to the different docs."
    )
    endpoints: EndpointsResponse = Field(
        ..., description="Paths to the different routes."
    )
    repository: HttpUrl = Field(
        ..., description="URL to the open source repository for the application."
    )
