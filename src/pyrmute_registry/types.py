"""Custom types."""

from typing import Any, NotRequired, TypeAlias, TypedDict

from pyrmute.avro_types import AvroRecordSchema

JsonValue: TypeAlias = (
    int | float | str | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
)
JsonSchema: TypeAlias = dict[str, JsonValue]


class RegistrySchemaResponse(TypedDict):
    """Response structure from registry get_schema endpoint."""

    id: int
    namespace: str | None
    model_name: str
    version: str
    json_schema: JsonSchema
    avro_schema: NotRequired[AvroRecordSchema]
    registered_at: str  # ISO format datetime
    registered_by: str
    meta: dict[str, Any]
    deprecated: bool
    deprecated_at: NotRequired[str]
    deprecation_message: NotRequired[str]
