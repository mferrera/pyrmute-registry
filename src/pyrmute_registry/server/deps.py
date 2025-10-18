"""FastAPI dependency injection utilities."""

from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .db import get_db
from .services.schema import SchemaService


def get_schema_service(
    db: Annotated[Session, Depends(get_db)],
) -> SchemaService:
    """Get schema service instance with database session.

    Args:
        db: Database session from dependency.

    Returns:
        Schema service instance.
    """
    return SchemaService(db)


DatabaseDep = Annotated[Session, Depends(get_db)]
SchemaServiceDep = Annotated[SchemaService, Depends(get_schema_service)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
