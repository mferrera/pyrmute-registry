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

from pyrmute_registry.server.logging import get_logger
from pyrmute_registry.server.models.schema import SchemaRecord
from pyrmute_registry.server.schemas.schema import (
    ComparisonResponse,
    SchemaCreate,
    SchemaListItem,
    SchemaListResponse,
    SchemaResponse,
)
from pyrmute_registry.server.utils.versioning import parse_version

logger = get_logger(__name__)


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
            logger.warning(
                "schema_validation_failed",
                namespace=namespace,
                model_name=model_name,
                version=schema_data.version,
                error_type="schema_error",
                error=str(e).split(chr(10))[0],
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Invalid JSON Schema: {str(e).split(chr(10))[0]}",
            ) from e
        except JsonSchemaValidationError as e:
            logger.warning(
                "schema_validation_failed",
                namespace=namespace,
                model_name=model_name,
                version=schema_data.version,
                error_type="validation_error",
                error=e.message,
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"Invalid JSON Schema: {e.message}",
            ) from e

        if schema_data.avro_schema is not None:
            try:
                self._validate_avro_schema(schema_data.avro_schema)
            except ValueError as e:
                logger.warning(
                    "avro_schema_validation_failed",
                    namespace=namespace,
                    model_name=model_name,
                    version=schema_data.version,
                    error=str(e),
                )
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=f"Invalid Avro schema: {e!s}",
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
            logger.warning(
                "schema_registration_failed",
                reason="already_exists",
                namespace=namespace,
                model_name=model_name,
                version=schema_data.version,
                identifier=identifier,
            )
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
            existing.avro_schema = schema_data.avro_schema
            existing.registered_at = registered_at
            existing.registered_by = schema_data.registered_by
            existing.meta = schema_data.meta
            record = existing
            operation = "updated"
        else:
            record = SchemaRecord(
                namespace=namespace,
                model_name=model_name,
                version=schema_data.version,
                json_schema=schema_data.json_schema,
                avro_schema=schema_data.avro_schema,
                registered_at=registered_at,
                registered_by=schema_data.registered_by,
                meta=schema_data.meta,
            )
            self.db.add(record)
            operation = "created"

        try:
            self.db.commit()
            self.db.refresh(record)

            has_avro = schema_data.avro_schema is not None
            logger.info(
                "schema_registered",
                operation=operation,
                namespace=namespace,
                model_name=model_name,
                version=schema_data.version,
                schema_id=record.id,
                identifier=record.full_identifier,
                registered_by=schema_data.registered_by,
                has_avro=has_avro,
            )
        except IntegrityError as e:
            self.db.rollback()
            logger.error(
                "schema_registration_failed",
                reason="integrity_error",
                namespace=namespace,
                model_name=model_name,
                version=schema_data.version,
                error=str(e),
            )
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

            logger.debug(
                "schema_not_found",
                namespace=namespace,
                model_name=model_name,
                version=version,
                identifier=identifier,
            )

            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Schema {identifier} not found",
            )

        logger.debug(
            "schema_retrieved",
            namespace=namespace,
            model_name=model_name,
            version=version,
            schema_id=record.id,
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
            logger.debug(
                "model_not_found",
                namespace=namespace,
                model_name=model_name,
                identifier=identifier,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Model {identifier} not found",
            )

        latest = max(records, key=lambda r: parse_version(r.version))

        logger.debug(
            "latest_schema_retrieved",
            namespace=namespace,
            model_name=model_name,
            version=latest.version,
            schema_id=latest.id,
            total_versions=len(records),
        )

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
            logger.debug(
                "model_not_found",
                namespace=namespace,
                model_name=model_name,
                identifier=identifier,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Model {identifier} not found",
            )

        versions = sorted(
            [r.version for r in records],
            key=parse_version,
        )

        logger.debug(
            "versions_listed",
            namespace=namespace,
            model_name=model_name,
            version_count=len(versions),
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
        if namespace is not None:
            if namespace in ("", "null"):
                query = query.filter(SchemaRecord.namespace.is_(None))
            else:
                query = query.filter(SchemaRecord.namespace == namespace)

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

        logger.debug(
            "schemas_listed",
            namespace_filter=namespace,
            model_name_filter=model_name,
            include_deprecated=include_deprecated,
            total_models=len(schema_items),
            total_schemas=total_count,
            limit=limit,
            offset=offset,
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
            logger.debug(
                "model_not_found_in_any_namespace",
                model_name=model_name,
            )
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

        logger.debug(
            "namespaces_listed_for_model",
            model_name=model_name,
            namespace_count=len(namespaces),
        )

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
            logger.debug(
                "schema_comparison_failed",
                reason="from_version_not_found",
                namespace=namespace,
                model_name=model_name,
                from_version=from_version,
                to_version=to_version,
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
            logger.debug(
                "schema_comparison_failed",
                reason="to_version_not_found",
                namespace=namespace,
                model_name=model_name,
                from_version=from_version,
                to_version=to_version,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Schema {identifier} not found",
            )

        changes = self._compare_schemas(from_record.json_schema, to_record.json_schema)

        logger.info(
            "schemas_compared",
            namespace=namespace,
            model_name=model_name,
            from_version=from_version,
            to_version=to_version,
            compatibility=changes["compatibility"],
            has_breaking_changes=len(changes["breaking_changes"]) > 0,
        )

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
                f"{namespace}::{model_name}@{version}"
                if namespace
                else f"{model_name}@{version}"
            )
            logger.warning(
                "schema_deletion_failed",
                reason="not_found",
                namespace=namespace,
                model_name=model_name,
                version=version,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Schema {identifier} not found",
            )

        if not force:
            logger.warning(
                "schema_deletion_failed",
                reason="force_required",
                namespace=namespace,
                model_name=model_name,
                version=version,
                schema_id=record.id,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Deletion requires force=true parameter",
            )

        schema_id = record.id
        identifier = record.full_identifier

        self.db.delete(record)
        self.db.commit()

        logger.info(
            "schema_deleted",
            namespace=namespace,
            model_name=model_name,
            version=version,
            schema_id=schema_id,
            identifier=identifier,
        )

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
            logger.warning(
                "schema_deprecation_failed",
                reason="not_found",
                namespace=namespace,
                model_name=model_name,
                version=version,
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

        logger.info(
            "schema_deprecated",
            namespace=namespace,
            model_name=model_name,
            version=version,
            schema_id=record.id,
            identifier=record.full_identifier,
            message=message,
        )

        return self._record_to_response(record)

    def get_schema_count(self: Self) -> int:
        """Get total count of registered schemas.

        Returns:
            Number of schemas.
        """
        count = self.db.query(SchemaRecord).count()
        logger.debug("schema_count_retrieved", count=count)
        return count

    @staticmethod
    def _record_to_response(record: SchemaRecord) -> SchemaResponse:
        """Convert database record to API response.

        Args:
            record: Database record.

        Returns:
            Schema response model.
        """
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

        response_data = {
            "id": record.id,
            "namespace": record.namespace,
            "model_name": record.model_name,
            "version": record.version,
            "json_schema": record.json_schema,
            "registered_at": registered_at_str,
            "registered_by": record.registered_by,
            "meta": record.meta or {},
            "deprecated": record.deprecated,
            "deprecated_at": deprecated_at_str,
            "deprecation_message": record.deprecation_message,
        }

        if record.avro_schema is not None:
            response_data["avro_schema"] = record.avro_schema

        return SchemaResponse.model_validate(response_data)

    @staticmethod
    def _compare_schemas(  # noqa: C901
        schema1: dict[str, Any],
        schema2: dict[str, Any],
        avro1: dict[str, Any] | None = None,
        avro2: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Compare two JSON schemas and return differences.

        Args:
            schema1: First schema.
            schema2: Second schema.
            avro1: First Avro schema (optional).
            avro2: Second Avro schema (optional).

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

        if avro1 is not None and avro2 is not None:
            avro_changes: dict[str, Any] = {
                "fields_added": [],
                "fields_removed": [],
                "fields_modified": [],
            }

            fields1 = {f["name"]: f for f in avro1.get("fields", [])}
            fields2 = {f["name"]: f for f in avro2.get("fields", [])}

            avro_changes["fields_added"] = list(
                set(fields2.keys()) - set(fields1.keys())
            )
            avro_changes["fields_removed"] = list(
                set(fields1.keys()) - set(fields2.keys())
            )

            # Check for type changes in common fields
            for field_name in set(fields1.keys()) & set(fields2.keys()):
                if fields1[field_name]["type"] != fields2[field_name]["type"]:
                    avro_changes["fields_modified"].append(
                        {
                            "field": field_name,
                            "from": fields1[field_name]["type"],
                            "to": fields2[field_name]["type"],
                        }
                    )

            changes["avro_changes"] = avro_changes

        return changes

    @staticmethod
    def _validate_avro_schema(avro_schema: dict[str, Any]) -> None:  # noqa: C901
        """Validate an Avro schema structure.

        Args:
            avro_schema: Avro schema to validate.

        Raises:
            ValueError: If schema is invalid.
        """
        if not isinstance(avro_schema, dict):
            raise ValueError("Avro schema must be a dictionary")

        schema_type = avro_schema.get("type")
        if schema_type != "record":
            raise ValueError(
                f"Avro schema must be of type 'record', got '{schema_type}'"
            )

        if "name" not in avro_schema:
            raise ValueError("Avro schema must have a 'name' field")

        if "fields" not in avro_schema:
            raise ValueError("Avro schema must have a 'fields' array")

        fields = avro_schema["fields"]
        if not isinstance(fields, list):
            raise ValueError("Avro schema 'fields' must be an array")

        if len(fields) == 0:
            raise ValueError("Avro schema 'fields' array cannot be empty")

        # Validate each field has required properties
        for i, field in enumerate(fields):
            if not isinstance(field, dict):
                raise ValueError(f"Field at index {i} must be a dictionary")

            if "name" not in field:
                raise ValueError(f"Field at index {i} is missing 'name'")

            if "type" not in field:
                raise ValueError(f"Field at index {i} is missing 'type'")
