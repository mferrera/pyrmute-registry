"""Version parsing and comparison utilities."""

from fastapi import HTTPException, status
from pyrmute import InvalidVersionError, ModelVersion


def parse_version(version: str) -> ModelVersion:
    """Parse semantic version string into a pyrmute ModelVersion.

    Args:
        version: Version string in format 'major.minor.patch'.

    Returns:
        ModelVersion instance.

    Raises:
        HTTPException: If version format is invalid.
    """
    try:
        return ModelVersion.parse(version)
    except InvalidVersionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Invalid version format '{version}': {e}. Expected 'major.minor.patch'"
            ),
        ) from e


def compare_versions(v1: str, v2: str) -> int:
    """Compare two semantic versions.

    Args:
        v1: First version string
        v2: Second version string

    Returns:
        -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
    """
    parsed_v1 = parse_version(v1)
    parsed_v2 = parse_version(v2)

    if parsed_v1 < parsed_v2:
        return -1
    if parsed_v1 > parsed_v2:
        return 1
    return 0
