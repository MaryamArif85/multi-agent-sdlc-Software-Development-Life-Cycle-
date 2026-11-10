```python
"""Secure JSON Log Processor Module.

Provides safe ingestion, path guard validation, schema enforcement,
and streaming batch processing for JSON log files.
"""

from pathlib import Path
import json
import logging
from typing import Dict, Any, List, Tuple, Optional, Iterator


# -----------------------------------------------------------------------------
# Custom Exceptions
# -----------------------------------------------------------------------------

class LogProcessorError(Exception):
    """Base exception for log processing operations."""


class SecurityValidationError(LogProcessorError):
    """Raised when security boundaries (path traversal, size limits) are violated."""


class LogParsingError(LogProcessorError):
    """Raised when log content cannot be parsed into a valid JSON structure."""


# -----------------------------------------------------------------------------
# Component Implementations
# -----------------------------------------------------------------------------

def setup_audit_logger(
    log_destination: Path, log_level: str = "INFO"
) -> logging.Logger:
    """Configures structured logging for operations and validation failures.

    Args:
        log_destination: Path where audit logs will be saved.
        log_level: Logging level (e.g., 'INFO', 'WARNING', 'ERROR').

    Returns:
        logging.Logger instance configured for structured JSON output.
    """
    logger = logging.getLogger("secure_json_log_processor")
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    if logger.handlers:
        return logger

    try:
        log_destination.parent.mkdir(parents=True, exist_ok=True)
    except OSError as err:
        raise LogProcessorError(
            f"Failed to create audit log directory: {err}"
        ) from err

    handler = logging.FileHandler(log_destination, encoding="utf-8")
    formatter = logging.Formatter(
        '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
        '"logger": "%(name)s", "event": %(message)s}'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


def safe_load_json(
    file_path: Path, base_dir: Path, max_bytes: int = 10_000_000
) -> List[Dict[str, Any]]:
    """Guards against path traversal, enforces file size limits (DoS prevention),
    and safely parses JSON log contents into memory.

    Args:
        file_path: Target log file path.
        base_dir: Restricted base directory boundary.
        max_bytes: Maximum allowed file size in bytes.

    Returns:
        List of log record dictionaries.

    Raises:
        SecurityValidationError: If path traversal or size limit check fails.
        LogParsingError: If file contains invalid JSON or non-object items.
        LogProcessorError: For general file access errors.
    """
    try:
        resolved_base = base_dir.resolve(strict=True)
    except FileNotFoundError as err:
        raise SecurityValidationError(
            f"Base directory does not exist: '{base_dir}'"
        ) from err

    try:
        resolved_file = file_path.resolve(strict=True)
    except FileNotFoundError as err:
        raise LogProcessorError(f"Log file not found: '{file_path}'") from err
    except OSError as err:
        raise SecurityValidationError(f"Path resolution error: {err}") from err

    # Security Check: Path Traversal
    try:
        resolved_file.relative_to(resolved_base)
    except ValueError as err:
        raise SecurityValidationError(
            f"Security Violation: Path traversal detected for '{file_path}' "
            f"outside base directory '{base_dir}'"
        ) from err

    # Security Check: Resource Bounds (DoS prevention)
    try:
        file_size = resolved_file.stat().st_size
    except OSError as err:
        raise LogProcessorError(
            f"Unable to stat file '{resolved_file}': {err}"
        ) from err

    if file_size > max_bytes:
        raise SecurityValidationError(
            f"Security Violation: File size ({file_size} bytes) exceeds maximum "
            f"limit of {max_bytes} bytes."
        )

    # Safe Read & Ingestion
    try:
        with resolved_file.open("r", encoding="utf-8") as file_stream:
            content = json.load(file_stream)
    except json.JSONDecodeError as err:
        raise LogParsingError(
            f"Malformed JSON in file '{resolved_file}': {err}"
        ) from err
    except OSError as err:
        raise LogProcessorError(
            f"I/O error reading file '{resolved_file}': {err}"
        ) from err

    # Structural Normalization
    if isinstance(content, dict):
        return [content]
    elif isinstance(content, list):
        if not all(isinstance(item, dict) for item in content):
            raise LogParsingError(
                f"Invalid record type in '{resolved_file}'. "
                f"All elements in array must be JSON objects."
            )
        return content
    else:
        raise LogParsingError(
            f"Invalid top-level JSON structure in '{resolved_file}'. "
            f"Expected object or array of objects."
        )


def validate_record(
    record: Dict[str, Any], schema: Dict[str, Any]
) -> Tuple[bool, Optional[str]]:
    """Validates log record against explicit schema rules and data types.

    Schema Format Example:
    {
        "timestamp": {"type": str, "required": True},
        "status_code": {"type": int, "required": False}
    }

    Args:
        record: JSON record to validate.
        schema: Rules specifying expected field types and requirement flags.

    Returns:
        Tuple of (is_valid, error_reason).
    """
    if not isinstance(record, dict):
        return False, "Record root must be a dictionary object."

    for field, rules in schema.items():
        expected_type = rules.get("type")
        is_required = rules.get("required", False)

        if field not in record:
            if is_required:
                return False, f"Missing required field: '{field}'"
            continue

        val = record[field]
        if expected_type is not None and not isinstance(val, expected_type):
            actual_type = type(val).__name__
            exp_name = (
                expected_type.__name__
                if hasattr(expected_type, "__name__")
                else str(expected_type)
            )
            return (
                False,
                f"Field '{field}' type mismatch. Expected {exp_name}, got {actual_type}.",
            )

    return True, None


def process_log_batches(
    input_files: List[Path],
    base_dir: Path,
    schema: Dict[str, Any],
    batch_size: int = 500,
    audit_logger: Optional[logging.Logger] = None,
) -> Iterator[List[Dict[str, Any]]]:
    """Streams validated records in batches. Isolates and logs broken files or 
    schema errors without interrupting pipeline execution.

    Args:
        input_files: List of file paths to process.
        base_dir: Allowed base directory boundary.
        schema: Validation schema rule set.
        batch_size: Maximum records per yielded batch.
        audit_logger: Optional Logger instance for recording bad records/files.

    Yields:
        Batches of validated log records as Lists of Dicts.
    """
    if batch_size <= 0:
        raise ValueError("batch_size must be a positive integer > 0.")

    batch: List[Dict[str, Any]] = []

    for file_path in input_files:
        try:
            records = safe_load_json(file_path, base_dir=base_dir)
        except LogProcessorError as err:
            if audit_logger:
                audit_logger.error(
                    json.dumps(
                        {"file": str(file_path), "error_type": type(err).__name__, "message": str(err)}
                    )
                )
            continue
        except Exception as err:
            if audit_logger:
                audit_logger.error(
                    json.dumps(
                        {"file": str(file_path), "error_type": "UnhandledException", "message": str(err)}
                    )
                )
            continue

        for record in records:
            is_valid, error_reason = validate_record(record, schema)
            if not is_valid:
                if audit_logger:
                    audit_logger.warning(
                        json.dumps(
                            {
                                "file": str(file_path),
                                "reason": error_reason,
                                "record": record,
                            }
                        )
                    )
                continue

            batch.append(record)

            if len(batch) >= batch_size:
                yield batch
                batch = []

    if batch:
        yield batch
```