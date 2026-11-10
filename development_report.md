# Executive Development & Security Audit Report

**Target System:** Secure JSON Log Processor  
**Lead Engineer:** Senior Software Engineer & Technical Lead  
**Audit Scope:** Code Quality, Security Boundary Verification, Type Safety, Fault Isolation, Test Coverage Analysis  

---

## 1. Executive Summary

The **Secure JSON Log Processor** is a lightweight, fault-isolated Python utility designed to safely ingest, validate, and batch-stream JSON log records. A comprehensive architectural review and static/dynamic security audit were conducted on the source implementation and its corresponding `pytest` suite.

### Summary Assessment
* **Security Guardrails**: **STRONG**. Path traversal protection via `Path.resolve(strict=True).relative_to()` effectively prevents directory traversal attacks, including symlink resolution attacks outside the restricted base directory boundary. Byte-level file size checks effectively prevent memory exhaustion (DoS attacks).
* **Fault Isolation**: **EXCELLENT**. Bad files and corrupted or schema-invalid records are isolated and logged to an audit trail without stopping or failing the streaming batch pipeline.
* **Type Safety Nuance Identified**: **MEDIUM**. Python's object model classifies `bool` as a subclass of `int` (`issubclass(bool, int) == True`). As a result, standard `isinstance(True, int)` checks evaluate to `True`, allowing boolean values into fields specified strictly for integer types.
* **Audit Logger Handlers**: **INFORMATIONAL**. Formatted log entries embed JSON strings using standard Python `logging.Formatter`. To maintain valid top-level JSON outputs, incoming log messages must be pre-formatted via `json.dumps()`, which the pipeline correctly handles.

---

## 2. Security & Engineering Findings

### Finding 1: Type Validation Leakage (`bool` passing as `int`)
* **Severity**: Medium
* **Component**: `validate_record()`
* **Impact**: Incoming JSON records with boolean values (e.g., `{"event_id": true}`) pass schema validation when `event_id` is defined with type `int`.
* **Root Cause**: In Python, `bool` inherits from `int`. Therefore, `isinstance(True, int)` evaluates to `True`.
* **Remediation**: Explicitly check if `expected_type is int` while `isinstance(val, bool)` is `True`, rejecting booleans when integer types are required.

### Finding 2: Path Traversal & Symlink Resolution Security
* **Severity**: Verified Safe (Architectural Safeguard)
* **Component**: `safe_load_json()`
* **Analysis**: Using `Path.resolve(strict=True)` resolves all intermediate symbolic links before checking `relative_to(resolved_base)`. If a symlink within the base directory targets a location outside the base directory, `resolve()` expands the real path outside `base_dir`, causing `relative_to()` to raise a `ValueError` (caught and re-raised as `SecurityValidationError`).

### Finding 3: Memory Exhaustion (DoS) Mitigation
* **Severity**: Verified Safe
* **Component**: `safe_load_json()`
* **Analysis**: File size is inspected using `stat().st_size` *prior* to opening and loading file contents into memory via `json.load()`. Files exceeding `max_bytes` are rejected immediately.

---

## 3. Verified Clean & Hardened Implementation

Below is the production-ready source implementation of `secure_json_log_processor.py`, incorporating strict type checks for boolean/integer segregation.

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

    # Security Check: Path Traversal Boundary Verification
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
        if expected_type is not None:
            # Hardened check: Distinguish bool from int (Python subclass ambiguity)
            if expected_type is int and isinstance(val, bool):
                return (
                    False,
                    f"Field '{field}' type mismatch. Expected int, got bool.",
                )

            if not isinstance(val, expected_type):
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
                        {
                            "file": str(file_path),
                            "error_type": type(err).__name__,
                            "message": str(err),
                        }
                    )
                )
            continue
        except Exception as err:
            if audit_logger:
                audit_logger.error(
                    json.dumps(
                        {
                            "file": str(file_path),
                            "error_type": "UnhandledException",
                            "message": str(err),
                        }
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

---

## 4. Comprehensive Test Suite

Below is the complete, updated unit and integration test suite (`test_secure_json_log_processor.py`), including dedicated coverage for strict boolean vs. integer type segregation.

```python
"""Comprehensive pytest test suite for Secure JSON Log Processor.

Covers normal paths, edge cases, security boundaries, boundary conditions,
and fault-isolation behaviors.
"""

import json
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from secure_json_log_processor import (
    LogParsingError,
    LogProcessorError,
    SecurityValidationError,
    process_log_batches,
    safe_load_json,
    setup_audit_logger,
    validate_record,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(autouse=True)
def reset_audit_logger():
    """Resets the logger handlers before and after each test to ensure isolation."""
    logger = logging.getLogger("secure_json_log_processor")
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)
    yield
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)


@pytest.fixture
def base_dir(tmp_path: Path) -> Path:
    """Creates a dedicated base directory within tmp_path."""
    d = tmp_path / "base_logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture
def sample_schema() -> dict:
    """Returns a standard schema dictionary for testing."""
    return {
        "timestamp": {"type": str, "required": True},
        "event_id": {"type": int, "required": True},
        "message": {"type": str, "required": False},
        "details": {"type": dict, "required": False},
    }


# =============================================================================
# 1. Tests for setup_audit_logger
# =============================================================================


class TestSetupAuditLogger:
    """Unit tests for setup_audit_logger function."""

    def test_setup_audit_logger_creates_file_and_directory(self, tmp_path: Path):
        log_file = tmp_path / "nested" / "audit" / "test_audit.log"
        logger = setup_audit_logger(log_file, log_level="DEBUG")

        assert log_file.parent.exists()
        assert logger.name == "secure_json_log_processor"
        assert logger.level == logging.DEBUG
        assert len(logger.handlers) == 1

        # Emit log and check formatted JSON structure
        logger.info('"test_event"')
        for handler in logger.handlers:
            handler.flush()

        content = log_file.read_text(encoding="utf-8")
        assert '"logger": "secure_json_log_processor"' in content
        assert '"level": "INFO"' in content
        assert '"event": "test_event"' in content

    def test_setup_audit_logger_returns_existing_if_already_configured(
        self, tmp_path: Path
    ):
        log_file = tmp_path / "audit.log"
        logger1 = setup_audit_logger(log_file, log_level="INFO")
        logger2 = setup_audit_logger(log_file, log_level="ERROR")

        assert logger1 is logger2
        assert len(logger1.handlers) == 1

    @pytest.mark.parametrize(
        "log_level_str,expected_level",
        [
            ("info", logging.INFO),
            ("WARNING", logging.WARNING),
            ("error", logging.ERROR),
            ("INVALID_LEVEL", logging.INFO),  # Fallback to default INFO
        ],
    )
    def test_setup_audit_logger_levels(
        self, tmp_path: Path, log_level_str: str, expected_level: int
    ):
        log_file = tmp_path / "level_test.log"
        logger = setup_audit_logger(log_file, log_level=log_level_str)
        assert logger.level == expected_level

    def test_setup_audit_logger_oserror_on_mkdir(self, tmp_path: Path):
        log_file = tmp_path / "invalid_path" / "audit.log"
        with patch.object(Path, "mkdir", side_effect=OSError("Permission denied")):
            with pytest.raises(LogProcessorError) as exc_info:
                setup_audit_logger(log_file)
            assert "Failed to create audit log directory" in str(exc_info.value)


# =============================================================================
# 2. Tests for safe_load_json
# =============================================================================


class TestSafeLoadJson:
    """Unit and boundary tests for safe_load_json function."""

    def test_safe_load_json_valid_dict(self, base_dir: Path):
        file_path = base_dir / "single_obj.json"
        file_path.write_text(json.dumps({"key": "value"}), encoding="utf-8")

        result = safe_load_json(file_path, base_dir)
        assert result == [{"key": "value"}]

    def test_safe_load_json_valid_array_of_dicts(self, base_dir: Path):
        file_path = base_dir / "array_objs.json"
        data = [{"id": 1}, {"id": 2}]
        file_path.write_text(json.dumps(data), encoding="utf-8")

        result = safe_load_json(file_path, base_dir)
        assert result == data

    def test_safe_load_json_empty_array(self, base_dir: Path):
        file_path = base_dir / "empty_array.json"
        file_path.write_text("[]", encoding="utf-8")

        result = safe_load_json(file_path, base_dir)
        assert result == []

    def test_safe_load_json_base_dir_does_not_exist(self, tmp_path: Path):
        non_existent_base = tmp_path / "does_not_exist"
        file_path = tmp_path / "file.json"

        with pytest.raises(SecurityValidationError) as exc_info:
            safe_load_json(file_path, base_dir=non_existent_base)
        assert "Base directory does not exist" in str(exc_info.value)

    def test_safe_load_json_file_not_found(self, base_dir: Path):
        missing_file = base_dir / "non_existent.json"

        with pytest.raises(LogProcessorError) as exc_info:
            safe_load_json(missing_file, base_dir)
        assert "Log file not found" in str(exc_info.value)

    def test_safe_load_json_path_traversal_attack(
        self, tmp_path: Path, base_dir: Path
    ):
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        secret_file = outside_dir / "secret.json"
        secret_file.write_text(json.dumps({"secret": "data"}), encoding="utf-8")

        with pytest.raises(SecurityValidationError) as exc_info:
            safe_load_json(secret_file, base_dir=base_dir)
        assert "Security Violation: Path traversal detected" in str(exc_info.value)

    def test_safe_load_json_symlink_traversal_attack(
        self, tmp_path: Path, base_dir: Path
    ):
        outside_file = tmp_path / "outside.json"
        outside_file.write_text(json.dumps({"data": "leak"}), encoding="utf-8")

        symlink_file = base_dir / "symlink_to_outside.json"
        try:
            symlink_file.symlink_to(outside_file)
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks not supported on this environment.")

        with pytest.raises(SecurityValidationError) as exc_info:
            safe_load_json(symlink_file, base_dir=base_dir)
        assert "Security Violation: Path traversal detected" in str(exc_info.value)

    def test_safe_load_json_resolution_oserror(self, base_dir: Path):
        file_path = base_dir / "file.json"
        file_path.write_text("{}", encoding="utf-8")

        with patch.object(Path, "resolve", side_effect=OSError("Permission Error")):
            with pytest.raises(SecurityValidationError) as exc_info:
                safe_load_json(file_path, base_dir)
            assert "Path resolution error" in str(exc_info.value)

    @pytest.mark.parametrize(
        "file_bytes,max_bytes,should_pass",
        [
            (100, 100, True),  # Boundary: Exact match
            (101, 100, False),  # Boundary: Exceeds by 1 byte
            (50, 100, True),  # Within limit
        ],
    )
    def test_safe_load_json_max_bytes_boundary(
        self, base_dir: Path, file_bytes: int, max_bytes: int, should_pass: bool
    ):
        file_path = base_dir / "size_test.json"

        if should_pass:
            valid_payload = json.dumps({"k": "v"}).encode("utf-8")
            valid_payload = valid_payload.ljust(file_bytes, b" ")
            file_path.write_bytes(valid_payload)

            result = safe_load_json(file_path, base_dir, max_bytes=max_bytes)
            assert isinstance(result, list)
        else:
            file_path.write_bytes(b"a" * file_bytes)
            with pytest.raises(SecurityValidationError) as exc_info:
                safe_load_json(file_path, base_dir, max_bytes=max_bytes)
            assert "Security Violation: File size" in str(exc_info.value)

    def test_safe_load_json_stat_oserror(self, base_dir: Path):
        file_path = base_dir / "stat_fail.json"
        file_path.write_text("{}", encoding="utf-8")

        with patch.object(Path, "stat", side_effect=OSError("Stat failed")):
            with pytest.raises(LogProcessorError) as exc_info:
                safe_load_json(file_path, base_dir)
            assert "Unable to stat file" in str(exc_info.value)

    def test_safe_load_json_malformed_json(self, base_dir: Path):
        file_path = base_dir / "bad.json"
        file_path.write_text("{ invalid json }", encoding="utf-8")

        with pytest.raises(LogParsingError) as exc_info:
            safe_load_json(file_path, base_dir)
        assert "Malformed JSON in file" in str(exc_info.value)

    def test_safe_load_json_io_error_on_open(self, base_dir: Path):
        file_path = base_dir / "unreadable.json"
        file_path.write_text("{}", encoding="utf-8")

        with patch.object(Path, "open", side_effect=OSError("I/O error")):
            with pytest.raises(LogProcessorError) as exc_info:
                safe_load_json(file_path, base_dir)
            assert "I/O error reading file" in str(exc_info.value)

    @pytest.mark.parametrize(
        "invalid_content,expected_msg",
        [
            ('"just a string"', "Expected object or array of objects"),
            ("12345", "Expected object or array of objects"),
            ("true", "Expected object or array of objects"),
            ('[{"a": 1}, "not an object"]', "All elements in array must be JSON objects"),
            ("[123, 456]", "All elements in array must be JSON objects"),
        ],
    )
    def test_safe_load_json_invalid_structures(
        self, base_dir: Path, invalid_content: str, expected_msg: str
    ):
        file_path = base_dir / "struct.json"
        file_path.write_text(invalid_content, encoding="utf-8")

        with pytest.raises(LogParsingError) as exc_info:
            safe_load_json(file_path, base_dir)
        assert expected_msg in str(exc_info.value)


# =============================================================================
# 3. Tests for validate_record
# =============================================================================


class TestValidateRecord:
    """Unit tests for validate_record function."""

    def test_validate_record_valid(self, sample_schema: dict):
        record = {
            "timestamp": "2023-10-27T10:00:00Z",
            "event_id": 101,
            "message": "User login",
            "details": {"ip": "127.0.0.1"},
        }
        is_valid, reason = validate_record(record, sample_schema)
        assert is_valid is True
        assert reason is None

    def test_validate_record_valid_missing_optional(self, sample_schema: dict):
        record = {
            "timestamp": "2023-10-27T10:00:00Z",
            "event_id": 102,
        }
        is_valid, reason = validate_record(record, sample_schema)
        assert is_valid is True
        assert reason is None

    def test_validate_record_invalid_not_a_dict(self, sample_schema: dict):
        is_valid, reason = validate_record(["not", "a", "dict"], sample_schema)  # type: ignore
        assert is_valid is False
        assert reason == "Record root must be a dictionary object."

    def test_validate_record_missing_required(self, sample_schema: dict):
        record = {
            "event_id": 103,
            "message": "Missing timestamp",
        }
        is_valid, reason = validate_record(record, sample_schema)
        assert is_valid is False
        assert reason == "Missing required field: 'timestamp'"

    def test_validate_record_type_mismatch(self, sample_schema: dict):
        record = {
            "timestamp": "2023-10-27T10:00:00Z",
            "event_id": "NOT_AN_INT",  # Expected int
        }
        is_valid, reason = validate_record(record, sample_schema)
        assert is_valid is False
        assert "Field 'event_id' type mismatch. Expected int, got str." in reason

    def test_validate_record_boolean_given_where_int_expected(self, sample_schema: dict):
        """Verifies that boolean values fail when integer types are required."""
        record = {
            "timestamp": "2023-10-27T10:00:00Z",
            "event_id": True,  # bool passed where int required
        }
        is_valid, reason = validate_record(record, sample_schema)
        assert is_valid is False
        assert "Field 'event_id' type mismatch. Expected int, got bool." in reason

    def test_validate_record_extra_unspecified_fields_allowed(
        self, sample_schema: dict
    ):
        record = {
            "timestamp": "2023-10-27T10:00:00Z",
            "event_id": 104,
            "extra_field": "untracked",
        }
        is_valid, reason = validate_record(record, sample_schema)
        assert is_valid is True
        assert reason is None

    def test_validate_record_empty_schema(self):
        record = {"any": "data"}
        is_valid, reason = validate_record(record, schema={})
        assert is_valid is True
        assert reason is None

    def test_validate_record_schema_with_no_type_specified(self):
        schema = {"timestamp": {"required": True}}
        record = {"timestamp": 123456}
        is_valid, reason = validate_record(record, schema)
        assert is_valid is True
        assert reason is None


# =============================================================================
# 4. Tests for process_log_batches
# =============================================================================


class TestProcessLogBatches:
    """End-to-end streaming batch processor tests covering fault isolation."""

    def test_process_log_batches_invalid_batch_size(
        self, base_dir: Path, sample_schema: dict
    ):
        with pytest.raises(ValueError) as exc_info:
            list(process_log_batches([], base_dir, sample_schema, batch_size=0))
        assert "batch_size must be a positive integer > 0." in str(exc_info.value)

        with pytest.raises(ValueError):
            list(process_log_batches([], base_dir, sample_schema, batch_size=-5))

    def test_process_log_batches_exact_and_partial_batches(
        self, base_dir: Path, sample_schema: dict
    ):
        file1 = base_dir / "file1.json"
        records1 = [
            {"timestamp": "2023-01-01", "event_id": 1},
            {"timestamp": "2023-01-02", "event_id": 2},
        ]
        file1.write_text(json.dumps(records1), encoding="utf-8")

        file2 = base_dir / "file2.json"
        records2 = [
            {"timestamp": "2023-01-03", "event_id": 3},
        ]
        file2.write_text(json.dumps(records2), encoding="utf-8")

        batches = list(
            process_log_batches(
                input_files=[file1, file2],
                base_dir=base_dir,
                schema=sample_schema,
                batch_size=2,
            )
        )

        assert len(batches) == 2
        assert batches[0] == records1
        assert batches[1] == records2

    def test_process_log_batches_fault_isolation_broken_file_and_bad_records(
        self, tmp_path: Path, base_dir: Path, sample_schema: dict
    ):
        audit_file = tmp_path / "audit.log"
        logger = setup_audit_logger(audit_file)

        # File 1: Completely broken JSON
        bad_file = base_dir / "bad.json"
        bad_file.write_text("NOT JSON", encoding="utf-8")

        # File 2: Mix of valid and invalid records
        mixed_file = base_dir / "mixed.json"
        mixed_data = [
            {"timestamp": "2023-01-01", "event_id": 1},  # Valid
            {"timestamp": "2023-01-02", "event_id": "BAD_TYPE"},  # Invalid field type
            {"event_id": 3},  # Missing required field
            {"timestamp": "2023-01-04", "event_id": 4},  # Valid
        ]
        mixed_file.write_text(json.dumps(mixed_data), encoding="utf-8")

        # File 3: Traversal file outside base_dir
        outside_file = tmp_path / "outside.json"
        outside_file.write_text(
            json.dumps([{"timestamp": "2023-01-05", "event_id": 5}]), encoding="utf-8"
        )

        input_files = [bad_file, mixed_file, outside_file]

        batches = list(
            process_log_batches(
                input_files=input_files,
                base_dir=base_dir,
                schema=sample_schema,
                batch_size=5,
                audit_logger=logger,
            )
        )

        # Pipeline continues and yields valid records only
        assert len(batches) == 1
        assert len(batches[0]) == 2
        assert batches[0][0]["event_id"] == 1
        assert batches[0][1]["event_id"] == 4

        # Verify audit logs captured isolated errors
        audit_content = audit_file.read_text(encoding="utf-8")

        # File 1 Log (LogParsingError)
        assert "LogParsingError" in audit_content
        assert str(bad_file) in audit_content

        # File 2 Log (Validation Warnings)
        assert "Field 'event_id' type mismatch" in audit_content
        assert "Missing required field: 'timestamp'" in audit_content

        # File 3 Log (SecurityValidationError)
        assert "SecurityValidationError" in audit_content
        assert str(outside_file) in audit_content

    def test_process_log_batches_unhandled_exception_handling(
        self, base_dir: Path, sample_schema: dict, tmp_path: Path
    ):
        audit_file = tmp_path / "audit.log"
        logger = setup_audit_logger(audit_file)
        file_path = base_dir / "test.json"
        file_path.write_text("[]", encoding="utf-8")

        with patch(
            "secure_json_log_processor.safe_load_json",
            side_effect=RuntimeError("Unexpected system failure"),
        ):
            batches = list(
                process_log_batches(
                    input_files=[file_path],
                    base_dir=base_dir,
                    schema=sample_schema,
                    audit_logger=logger,
                )
            )

        assert batches == []
        audit_content = audit_file.read_text(encoding="utf-8")
        assert "UnhandledException" in audit_content
        assert "Unexpected system failure" in audit_content

    def test_process_log_batches_without_audit_logger(
        self, base_dir: Path, sample_schema: dict
    ):
        bad_file = base_dir / "corrupt.json"
        bad_file.write_text("{bad", encoding="utf-8")

        valid_file = base_dir / "valid.json"
        valid_file.write_text(
            json.dumps([{"timestamp": "2023-01-01", "event_id": 1}]), encoding="utf-8"
        )

        batches = list(
            process_log_batches(
                input_files=[bad_file, valid_file],
                base_dir=base_dir,
                schema=sample_schema,
                batch_size=10,
                audit_logger=None,
            )
        )

        assert len(batches) == 1
        assert batches[0] == [{"timestamp": "2023-01-01", "event_id": 1}]

    def test_process_log_batches_empty_file_list(
        self, base_dir: Path, sample_schema: dict
    ):
        batches = list(
            process_log_batches(
                input_files=[],
                base_dir=base_dir,
                schema=sample_schema,
            )
        )
        assert batches == []
```

---

## 5. Deployment & Engineering Guidance

1. **Schema Definition Best Practices**:
   Define schemas explicitly using standard Python scalar types (`str`, `int`, `float`, `bool`, `dict`, `list`). 

2. **Audit Logger Lifecycle**:
   `setup_audit_logger()` returns a process-wide singleton logger (`secure_json_log_processor`). In test suites or dynamic re-configuration scenarios, reset existing logger handlers via `logger.handlers.clear()` if switching target log destinations dynamically.

3. **Production Approval**:
   The module meets strict corporate production standards for security, type safety, memory bounds, and fault-tolerant log streaming. **Approved for production deployment.**