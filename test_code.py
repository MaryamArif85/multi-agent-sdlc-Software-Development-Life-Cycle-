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

    @pytest.mark.parametrize("log_level_str,expected_level", [
        ("info", logging.INFO),
        ("WARNING", logging.WARNING),
        ("error", logging.ERROR),
        ("INVALID_LEVEL", logging.INFO),  # Fallback to default INFO
    ])
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

    def test_safe_load_json_path_traversal_attack(self, tmp_path: Path, base_dir: Path):
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()
        secret_file = outside_dir / "secret.json"
        secret_file.write_text(json.dumps({"secret": "data"}), encoding="utf-8")

        # Attempt to access outside_file referencing base_dir
        with pytest.raises(SecurityValidationError) as exc_info:
            safe_load_json(secret_file, base_dir=base_dir)
        assert "Security Violation: Path traversal detected" in str(exc_info.value)

    def test_safe_load_json_symlink_traversal_attack(self, tmp_path: Path, base_dir: Path):
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

    @pytest.mark.parametrize("file_bytes,max_bytes,should_pass", [
        (100, 100, True),     # Boundary: Exact match
        (101, 100, False),    # Boundary: Exceeds by 1 byte
        (50, 100, True),      # Within limit
    ])
    def test_safe_load_json_max_bytes_boundary(
        self, base_dir: Path, file_bytes: int, max_bytes: int, should_pass: bool
    ):
        file_path = base_dir / "size_test.json"
        # Generate exact byte size string content representing valid JSON structure
        raw_data = {"a": "x" * (file_bytes - 9)}  # {"a":"xxx..."}
        content = json.dumps(raw_data).encode("utf-8")
        
        # Pad or trim to exact required byte size safely
        if len(content) < file_bytes:
            padding = file_bytes - len(content)
            raw_data = {"a": "x" * (file_bytes - 9 - padding + 1)}
            content = json.dumps(raw_data).encode("utf-8")
        
        file_path.write_bytes(b"a" * file_bytes)

        if should_pass:
            # Re-write valid JSON matching length exactly
            valid_json_payload = json.dumps({"k": "v"}).encode("utf-8")
            valid_json_payload = valid_json_payload.ljust(file_bytes, b" ")
            file_path.write_bytes(valid_json_payload)

            result = safe_load_json(file_path, base_dir, max_bytes=max_bytes)
            assert isinstance(result, list)
        else:
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

    @pytest.mark.parametrize("invalid_content,expected_msg", [
        ('"just a string"', "Expected object or array of objects"),
        ("12345", "Expected object or array of objects"),
        ("true", "Expected object or array of objects"),
        ('[{"a": 1}, "not an object"]', "All elements in array must be JSON objects"),
        ('[123, 456]', "All elements in array must be JSON objects"),
    ])
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

    def test_validate_record_extra_unspecified_fields_allowed(self, sample_schema: dict):
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

    def test_process_log_batches_invalid_batch_size(self, base_dir: Path, sample_schema: dict):
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

        # Should execute silently and omit corrupted files/records without throwing
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

    def test_process_log_batches_empty_file_list(self, base_dir: Path, sample_schema: dict):
        batches = list(
            process_log_batches(
                input_files=[],
                base_dir=base_dir,
                schema=sample_schema,
            )
        )
        assert batches == []
```