# Technical Architecture Specification: Secure JSON Log Processor

## 1. System Overview
A lightweight, modular Python utility designed for safe ingestion, schema validation, and streaming batch processing of JSON log files with fault-isolated error handling.

```
[File Stream] -> [Path/Size Guard] -> [Safe JSON Parser] -> [Schema Validator] -> [Batch Generator] -> [Sink]
                                                                  │ (Invalid Record)
                                                                  └──> [Structured Audit Log]
```

## 2. Component Design & Function Signatures

```python
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Iterator
import logging

def setup_audit_logger(log_destination: Path, log_level: str = "INFO") -> logging.Logger:
    """Configures structured logging for operations and validation failures."""
    ...

def safe_load_json(file_path: Path, base_dir: Path, max_bytes: int = 10_000_000) -> List[Dict[str, Any]]:
    """
    Guards against path traversal, enforces file size limits (DoS prevention),
    and safely parses JSON log contents into memory.
    """
    ...

def validate_record(record: Dict[str, Any], schema: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """Validates log record against explicit schema rules and data types."""
    ...

def process_log_batches(
    input_files: List[Path],
    base_dir: Path,
    schema: Dict[str, Any],
    batch_size: int = 500
) -> Iterator[List[Dict[str, Any]]]:
    """
    Streams validated records in batches. Isolates and logs broken files or 
    schema errors without interrupting pipeline execution.
    """
    ...
```

## 3. Security & Resilience Strategy
* **Path Traversal Protection**: Enforces `file_path.resolve().is_relative_to(base_dir)`.
* **Resource Bounds**: Enforces maximum file byte limits prior to reading into memory.
* **Fault Isolation**: Per-record validation failure routes corrupted records to an audit logger while valid records proceed in the stream.