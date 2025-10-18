"""Business logic for schema operations."""

from datetime import UTC, datetime
from typing import Any, Self

from fastapi import HTTPException, status
from jsonschema import (
    Draft202012Validator,
    SchemaError,
    ValidationError as JsonSchemaValidationError,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pyrmute_registry.server.models.schema import SchemaRecord
from pyrmute_registry.server.schemas.schema import (
    ComparisonResponse,
    SchemaCreate,
    SchemaListItem,
    SchemaListResponse,
    SchemaResponse,
)
from pyrmute_registry.server.utils.versioning import parse_version


def _parse_iso_datetime(dt_str: str) -> datetime:
    """Replace 'Z' (Zulu) with '+00:00' for proper ISO 8601 parsing."""
    if dt_str.endswith("Z"):
        dt_str = dt_str[:-1] + "+00:00"
    return datetime.fromisoformat(dt_str)


class SchemaService:
    """Service layer for schema operations."""

    def __init__(self: Self, db: Session) -> None:
        """Initialize service with database session.

        Args:
            db: SQLAlchemy database session.
        """
        self.db = db

    def register_schema(
        self: Self,
        namespace: str | None,
        model_name: str,
        schema_data: SchemaCreate,
        allow_overwrite: bool = False,
    ) -> SchemaResponse:
        """Register a new schema version.

        Args:
            namespace: Optional namespace for scoping (None for global schemas).
            model_name: Name of the model.
            schema_data: Schema data to register.
            allow_overwrite: Whether to allow overwriting existing schema.

        Returns:
            Registered schema response.

        Raises:
            HTTPException: If schema exists and overwrite not allowed, or on DB error.
        """
        parse_version(schema_data.version)

        try:
            Draft202012Validator.check_schema(schema_data.json_schema)
        except SchemaError as e:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Invalid JSON Schema: {str(e).split(chr(10))[0]}",
            ) from e
        except JsonSchemaValidationError as e:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Invalid JSON Schema: {e.message}",
            ) from e

        existing = (
            self.db.query(SchemaRecord)
            .filter(
                SchemaRecord.namespace == namespace,
                SchemaRecord.model_name == model_name,
                SchemaRecord.version == schema_data.version,
            )
            .first()
        )

        if existing and not allow_overwrite:
            identifier = existing.full_identifier
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Schema {identifier} already exists. Use allow_overwrite=true "
                    "to replace it."
                ),
            )

        registered_at = _parse_iso_datetime(schema_data.registered_at)

        if existing:
            existing.json_schema = schema_data.json_schema
            existing.registered_at = registered_at
            existing.registered_by = schema_data.registered_by
            existing.meta = schema_data.meta
            record = existing
        else:
            record = SchemaRecord(
                namespace=namespace,
                model_name=model_name,
                version=schema_data.version,
                json_schema=schema_data.json_schema,
                registered_at=registered_at,
                registered_by=schema_data.registered_by,
                meta=schema_data.meta,
            )
            self.db.add(record)

        try:
            self.db.commit()
            self.db.refresh(record)
        except IntegrityError as e:
            self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Schema conflict: {e!s}",
            ) from e

        return self._record_to_response(record)

    def get_schema(
        self: Self, namespace: str | None, model_name: str, version: str
    ) -> SchemaResponse:
        """Get a specific schema version.

        Args:
            namespace: Optional namespace for scoping (None for global schemas).
            model_name: Name of the model.
            version: Version string.

        Returns:
            Schema response.

        Raises:
            HTTPException: If schema not found.
        """
        record = (
            self.db.query(SchemaRecord)
            .filter(
                SchemaRecord.namespace == namespace,
                SchemaRecord.model_name == model_name,
                SchemaRecord.version == version,
            )
            .first()
        )

        if not record:
            if namespace:
                identifier = f"{namespace}::{model_name}@{version}"
            else:
                identifier = f"{model_name}@{version}"

            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Schema {identifier} not found",
            )

        return self._record_to_response(record)

    def get_latest_schema(
        self: Self, namespace: str | None, model_name: str
    ) -> SchemaResponse:
        """Get the latest version of a schema.

        Args:
            namespace: Optional namespace for scoping (None for global schemas).
            model_name: Name of the model.

        Returns:
            Latest schema version.

        Raises:
            HTTPException: If model not found.
        """
        records = (
            self.db.query(SchemaRecord)
            .filter(
                SchemaRecord.namespace == namespace,
                SchemaRecord.model_name == model_name,
            )
            .all()
        )

        if not records:
            identifier = f"{namespace}::{model_name}" if namespace else model_name
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Model {identifier} not found",
            )

        latest = max(records, key=lambda r: parse_version(r.version))
        return self._record_to_response(latest)

    def list_versions(
        self: Self, namespace: str | None, model_name: str
    ) -> dict[str, list[str]]:
        """List all versions for a model.

        Args:
            namespace: Optional namespace for scoping (None for global schemas).
            model_name: Name of the model.

        Returns:
            Dictionary with list of versions.

        Raises:
            HTTPException: If model not found.
        """
        records = (
            self.db.query(SchemaRecord)
            .filter(
                SchemaRecord.namespace == namespace,
                SchemaRecord.model_name == model_name,
            )
            .all()
        )

        if not records:
            identifier = f"{namespace}::{model_name}" if namespace else model_name
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Model {identifier} not found",
            )

        versions = sorted(
            [r.version for r in records],
            key=parse_version,
        )

        return {"versions": versions}

    def list_schemas(
        self: Self,
        namespace: str | None = None,
        model_name: str | None = None,
        include_deprecated: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> SchemaListResponse:
        """List all registered schemas with pagination and filtering.

        Args:
            namespace: Optional filter by namespace.
                - None (default): List schemas from ALL namespaces.
                - "" or "null": Filter for global schemas only (namespace IS NULL).
                - "service-name": Filter for specific namespace.
            model_name: Optional filter by model name.
            include_deprecated: Whether to include deprecated schemas.
            limit: Maximum number of results.
            offset: Number of results to skip.

        Returns:
            List of schema summaries with pagination info.
        """
        query = self.db.query(SchemaRecord)

        # Filter by namespace if specified
        # namespace=None means "all namespaces" (no filter)
        # namespace="" or "null" means "global schemas only"
        # namespace="service-name" means "specific namespace"
        if namespace is not None:
            if namespace in ("", "null"):
                # Filter for global schemas only
                query = query.filter(SchemaRecord.namespace.is_(None))
            else:
                # Filter for specific namespace
                query = query.filter(SchemaRecord.namespace == namespace)
        # If namespace is None, don't apply any namespace filter (list all)

        # Filter by model name if specified
        if model_name:
            query = query.filter(SchemaRecord.model_name == model_name)

        # Filter deprecated schemas unless explicitly included
        if not include_deprecated:
            query = query.filter(SchemaRecord.deprecated.is_(False))

        total_count = query.count()
        records = query.offset(offset).limit(limit).all()

        # Group by namespace and model name
        models: dict[tuple[str | None, str], list[SchemaRecord]] = {}
        for record in records:
            key = (record.namespace, record.model_name)
            if key not in models:
                models[key] = []
            models[key].append(record)

        # Build response
        schema_items: list[SchemaListItem] = []
        for (ns, mdl_name), model_records in models.items():
            versions = sorted(
                [r.version for r in model_records],
                key=parse_version,
            )
            latest = versions[-1] if versions else None
            services = {r.registered_by for r in model_records}

            deprecated_versions = sorted(
                [r.version for r in model_records if r.deprecated],
                key=parse_version,
            )

            schema_items.append(
                SchemaListItem(
                    namespace=ns,
                    model_name=mdl_name,
                    versions=versions,
                    latest_version=latest,
                    registered_by=services,
                    deprecated_versions=deprecated_versions,
                )
            )

        return SchemaListResponse(
            schemas=schema_items,
            total=len(schema_items),
            limit=limit,
            offset=offset,
            total_count=total_count,
        )

    def list_namespaces_for_model(self: Self, model_name: str) -> dict[str, Any]:
        """List all namespaces that have versions of a specific model.

        Args:
            model_name: Name of the model to search for.

        Returns:
            Dictionary mapping namespaces to lists of versions.
        """
        records = (
            self.db.query(SchemaRecord)
            .filter(SchemaRecord.model_name == model_name)
            .all()
        )

        if not records:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Model {model_name} not found in any namespace",
            )

        # Group by namespace
        namespaces: dict[str, list[str]] = {}
        for record in records:
            ns_key = record.namespace if record.namespace else "null"
            if ns_key not in namespaces:
                namespaces[ns_key] = []
            namespaces[ns_key].append(record.version)

        # Sort versions within each namespace
        for ns, versions in namespaces.items():
            namespaces[ns] = sorted(versions, key=parse_version)

        return {"namespaces": namespaces}

    def compare_versions(
        self: Self,
        namespace: str | None,
        model_name: str,
        from_version: str,
        to_version: str,
    ) -> ComparisonResponse:
        """Compare two schema versions.

        Args:
            namespace: Optional namespace for scoping (None for global schemas).
            model_name: Name of the model.
            from_version: Source version.
            to_version: Target version.

        Returns:
            Comparison result with changes.

        Raises:
            HTTPException: If either version not found.
        """
        from_record = (
            self.db.query(SchemaRecord)
            .filter(
                SchemaRecord.namespace == namespace,
                SchemaRecord.model_name == model_name,
                SchemaRecord.version == from_version,
            )
            .first()
        )

        to_record = (
            self.db.query(SchemaRecord)
            .filter(
                SchemaRecord.namespace == namespace,
                SchemaRecord.model_name == model_name,
                SchemaRecord.version == to_version,
            )
            .first()
        )

        if not from_record:
            identifier = (
                f"{namespace}::{model_name}@{from_version}"
                if namespace
                else f"{model_name}@{from_version}"
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Schema {identifier} not found",
            )

        if not to_record:
            identifier = (
                f"{namespace}::{model_name}@{to_version}"
                if namespace
                else f"{model_name}@{to_version}"
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Schema {identifier} not found",
            )

        changes = self._compare_schemas(from_record.json_schema, to_record.json_schema)

        return ComparisonResponse(
            namespace=namespace,
            model_name=model_name,
            from_version=from_version,
            to_version=to_version,
            changes=changes,
        )

    def delete_schema(
        self: Self,
        namespace: str | None,
        model_name: str,
        version: str,
        force: bool = False,
    ) -> bool:
        """Delete a schema version.

        Args:
            namespace: Optional namespace for scoping (None for global schemas).
            model_name: Name of the model.
            version: Version to delete.
            force: Force deletion without safety check.

        Returns:
            True if deleted successfully.

        Raises:
            HTTPException: If schema not found or force not specified.
        """
        record = (
            self.db.query(SchemaRecord)
            .filter(
                SchemaRecord.namespace == namespace,
                SchemaRecord.model_name == model_name,
                SchemaRecord.version == version,
            )
            .first()
        )

        if not record:
            identifier = (
                record.full_identifier
                if record
                else (
                    f"{namespace}::{model_name}@{version}"
                    if namespace
                    else f"{model_name}@{version}"
                )
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Schema {identifier} not found",
            )

        if not force:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Deletion requires force=true parameter",
            )

        self.db.delete(record)
        self.db.commit()

        return True

    def deprecate_schema(
        self: Self,
        namespace: str | None,
        model_name: str,
        version: str,
        message: str | None = None,
    ) -> SchemaResponse:
        """Mark a schema version as deprecated.

        Args:
            namespace: Optional namespace for scoping (None for global schemas).
            model_name: Name of the model.
            version: Version to deprecate.
            message: Optional deprecation message.

        Returns:
            Updated schema response.

        Raises:
            HTTPException: If schema not found.
        """
        record = (
            self.db.query(SchemaRecord)
            .filter(
                SchemaRecord.namespace == namespace,
                SchemaRecord.model_name == model_name,
                SchemaRecord.version == version,
            )
            .first()
        )

        if not record:
            identifier = (
                f"{namespace}::{model_name}@{version}"
                if namespace
                else f"{model_name}@{version}"
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Schema {identifier} not found",
            )

        record.deprecated = True
        record.deprecated_at = datetime.now(UTC)
        record.deprecation_message = message

        self.db.commit()
        self.db.refresh(record)

        return self._record_to_response(record)

    def get_schema_count(self: Self) -> int:
        """Get total count of registered schemas.

        Returns:
            Number of schemas.
        """
        return self.db.query(SchemaRecord).count()

    @staticmethod
    def _record_to_response(record: SchemaRecord) -> SchemaResponse:
        """Convert database record to API response.

        Args:
            record: Database record.

        Returns:
            Schema response model.
        """
        # Ensure timezone info. SQLite needs this, for example.
        registered_at = record.registered_at
        if registered_at.tzinfo is None:
            registered_at = registered_at.replace(tzinfo=UTC)

        registered_at_str = registered_at.isoformat().replace("+00:00", "Z")

        deprecated_at_str = None
        if record.deprecated_at:
            deprecated_at = record.deprecated_at
            if deprecated_at.tzinfo is None:
                deprecated_at = deprecated_at.replace(tzinfo=UTC)
            deprecated_at_str = deprecated_at.isoformat().replace("+00:00", "Z")

        return SchemaResponse(
            id=record.id,
            namespace=record.namespace,
            model_name=record.model_name,
            version=record.version,
            json_schema=record.json_schema,
            registered_at=registered_at_str,
            registered_by=record.registered_by,
            meta=record.meta or {},
            deprecated=record.deprecated,
            deprecated_at=deprecated_at_str,
            deprecation_message=record.deprecation_message,
        )

    @staticmethod
    def _compare_schemas(
        schema1: dict[str, Any],
        schema2: dict[str, Any],
    ) -> dict[str, Any]:
        """Compare two JSON schemas and return differences.

        Args:
            schema1: First schema.
            schema2: Second schema.

        Returns:
            Dictionary of changes with breaking change analysis.
        """
        changes: dict[str, Any] = {
            "properties_added": [],
            "properties_removed": [],
            "properties_modified": [],
            "required_added": [],
            "required_removed": [],
            "breaking_changes": [],
            "compatibility": "unknown",
        }

        props1 = schema1.get("properties", {})
        props2 = schema2.get("properties", {})

        # Check properties
        keys1 = set(props1.keys())
        keys2 = set(props2.keys())

        changes["properties_added"] = list(keys2 - keys1)
        changes["properties_removed"] = list(keys1 - keys2)

        # Breaking change: removing properties
        if changes["properties_removed"]:
            changes["breaking_changes"].append(
                {
                    "type": "properties_removed",
                    "details": changes["properties_removed"],
                    "description": (
                        "Removing properties can break consumers expecting these fields"
                    ),
                }
            )

        # Check for modified properties
        for key in keys1 & keys2:
            if props1[key] != props2[key]:
                # Check if type changed (breaking)
                old_type = props1[key].get("type")
                new_type = props2[key].get("type")

                if old_type != new_type:
                    changes["breaking_changes"].append(
                        {
                            "type": "type_changed",
                            "property": key,
                            "from": old_type,
                            "to": new_type,
                            "description": (
                                f"Property '{key}' type changed from "
                                f"{old_type} to {new_type}"
                            ),
                        }
                    )

                changes["properties_modified"].append(
                    {
                        "property": key,
                        "from": props1[key],
                        "to": props2[key],
                    }
                )

        # Check required fields
        req1 = set(schema1.get("required", []))
        req2 = set(schema2.get("required", []))

        changes["required_added"] = list(req2 - req1)
        changes["required_removed"] = list(req1 - req2)

        # Breaking change: adding required fields
        if changes["required_added"]:
            changes["breaking_changes"].append(
                {
                    "type": "required_fields_added",
                    "details": changes["required_added"],
                    "description": (
                        "Adding required fields can break existing data producers"
                    ),
                }
            )

        # Assess overall compatibility
        if changes["breaking_changes"]:
            changes["compatibility"] = "breaking"
        elif any(
            [
                changes["properties_added"],
                changes["properties_modified"],
                changes["required_removed"],
            ]
        ):
            changes["compatibility"] = "backward_compatible"
        else:
            changes["compatibility"] = "identical"

        return changes
