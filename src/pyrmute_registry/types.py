"""Custom types."""

from typing import TypeAlias

JsonValue: TypeAlias = (
    int | float | str | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
)
JsonSchema: TypeAlias = dict[str, JsonValue]
