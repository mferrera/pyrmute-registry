"""FastAPI dependency injection utilities."""

from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .db import get_db
from .services.api_key import ApiKeyService
from .services.schema import SchemaService

DbDep = Annotated[Session, Depends(get_db)]


def get_schema_service(db: DbDep) -> SchemaService:
    """Get schema service instance with database session.

    Args:
        db: Database session from dependency.

    Returns:
        SchemaService instance.
    """
    return SchemaService(db)


def get_api_key_service(db: DbDep) -> ApiKeyService:
    """Get API key service instance.

    Args:
        db: Database session from dependency.

    Returns:
        ApiKeyService instance.
    """
    return ApiKeyService(db)


ApiKeyServiceDep = Annotated[ApiKeyService, Depends(get_api_key_service)]
SchemaServiceDep = Annotated[SchemaService, Depends(get_schema_service)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
