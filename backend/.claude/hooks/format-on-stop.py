#!/usr/bin/env python3
"""
Stop Hook - Auto-Format on Completion

This hook runs when Claude finishes responding (after all edits are complete).
It formats all modified Python files in batch to avoid conflicts during editing.

Features:
- Git-based detection of modified files
- Batch Black + isort formatting
- Flake8 critical error checks
- Detailed reporting
- No blocking on errors

Usage: Automatically triggered by Claude Code on Stop event
"""

import datetime
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Debug log file
DEBUG_LOG = "/tmp/claude-stop-hook-debug.log"

# ============================================================================
# Configuration
# ============================================================================

# Timeouts
GIT_TIMEOUT = 10  # seconds
FORMAT_TIMEOUT = 30  # seconds
FLAKE8_TIMEOUT = 30  # seconds

# Exclude patterns
EXCLUDE_PATTERNS = [
    "venv/",
    ".venv/",
    "env/",
    "__pycache__/",
    "site-packages/",
    ".pytest_cache/",
    "node_modules/",
    "migrations/",  # Database migrations
    "test_",  # Test files (usually don't need auto-format)
]

# Flake8 critical error codes
FLAKE8_CRITICAL_ERRORS = "E9,F63,F7,F82"


# ============================================================================
# Utility Functions
# ============================================================================


def load_input() -> dict:
    """Load JSON input from stdin (if available)"""
    try:
        if not sys.stdin.isatty():
            return json.load(sys.stdin)
        return {}
    except json.JSONDecodeError:
        return {}
    except Exception:
        return {}


def get_tool_path(tool_name: str, project_dir: str) -> str:
    """
    Get path to tool, preferring venv version

    Args:
        tool_name: Tool name (e.g., "black", "isort", "flake8")
        project_dir: Project root directory

    Returns:
        Path to tool executable
    """
    venv_path = os.path.join(project_dir, "venv", "bin", tool_name)
    if os.path.exists(venv_path) and os.access(venv_path, os.X_OK):
        return venv_path
    return tool_name  # Fallback to system-wide tool


def should_exclude_file(file_path: str) -> bool:
    """Check if file should be excluded from formatting"""
    return any(pattern in file_path for pattern in EXCLUDE_PATTERNS)


# ============================================================================
# Git Operations
# ============================================================================


def get_modified_python_files(project_dir: str) -> List[str]:
    """
    Get list of modified Python files using git

    Strategy:
    1. Get unstaged changes (git diff --name-only)
    2. Filter for .py files
    3. Check file exists
    4. Apply exclude patterns

    Returns:
        List of Python file paths
    """
    try:
        os.chdir(project_dir)

        # Get unstaged changes
        result = subprocess.run(
            ["git", "diff", "--name-only"],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT,
        )

        if result.returncode != 0:
            print(f"Warning: git diff failed: {result.stderr}", file=sys.stderr)
            return []

        # Parse output
        files = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]

        # Filter for Python files that exist and should not be excluded
        python_files = [
            f
            for f in files
            if f.endswith(".py") and os.path.exists(f) and not should_exclude_file(f)
        ]

        return python_files

    except subprocess.TimeoutExpired:
        print(
            f"Warning: git command timed out after {GIT_TIMEOUT}s",
            file=sys.stderr,
        )
        return []
    except Exception as e:
        print(
            f"Warning: Failed to detect modified files: {type(e).__name__}: {e}",
            file=sys.stderr,
        )
        return []


# ============================================================================
# Formatting Operations
# ============================================================================


def run_black(files: List[str], project_dir: str) -> Tuple[bool, str]:
    """
    Run Black formatter on files

    Returns:
        (success, message)
    """
    try:
        black_cmd = get_tool_path("black", project_dir)

        result = subprocess.run(
            [black_cmd] + files,
            capture_output=True,
            text=True,
            timeout=FORMAT_TIMEOUT,
        )

        if result.returncode == 0:
            return True, "Black formatting applied successfully"
        else:
            error_msg = result.stderr or result.stdout
            return False, f"Black encountered issues: {error_msg[:200]}"

    except FileNotFoundError:
        return False, "Black not found. Install: pip install black"
    except subprocess.TimeoutExpired:
        return False, f"Black timed out after {FORMAT_TIMEOUT}s"
    except Exception as e:
        return False, f"Black error: {type(e).__name__}: {e}"


def run_isort(files: List[str], project_dir: str) -> Tuple[bool, str]:
    """
    Run isort import sorter on files

    Returns:
        (success, message)
    """
    try:
        isort_cmd = get_tool_path("isort", project_dir)

        result = subprocess.run(
            [isort_cmd] + files,
            capture_output=True,
            text=True,
            timeout=FORMAT_TIMEOUT,
        )

        if result.returncode == 0:
            return True, "Import sorting applied successfully"
        else:
            error_msg = result.stderr or result.stdout
            return False, f"isort encountered issues: {error_msg[:200]}"

    except FileNotFoundError:
        return False, "isort not found. Install: pip install isort"
    except subprocess.TimeoutExpired:
        return False, f"isort timed out after {FORMAT_TIMEOUT}s"
    except Exception as e:
        return False, f"isort error: {type(e).__name__}: {e}"


def run_flake8(files: List[str], project_dir: str) -> Tuple[bool, List[str]]:
    """
    Run Flake8 critical checks on files

    Returns:
        (success, error_lines)
    """
    try:
        flake8_cmd = get_tool_path("flake8", project_dir)

        result = subprocess.run(
            [flake8_cmd, f"--select={FLAKE8_CRITICAL_ERRORS}"] + files,
            capture_output=True,
            text=True,
            timeout=FLAKE8_TIMEOUT,
        )

        if result.returncode == 0:
            return True, []
        else:
            # Flake8 returns non-zero when errors found
            error_lines = [
                line.strip()
                for line in result.stdout.strip().split("\n")
                if line.strip()
            ]
            return False, error_lines

    except FileNotFoundError:
        return False, ["Flake8 not found. Install: pip install flake8"]
    except subprocess.TimeoutExpired:
        return False, [f"Flake8 timed out after {FLAKE8_TIMEOUT}s"]
    except Exception as e:
        return False, [f"Flake8 error: {type(e).__name__}: {e}"]


# ============================================================================
# Report Generation
# ============================================================================


def generate_report(
    files: List[str],
    black_result: Tuple[bool, str],
    isort_result: Tuple[bool, str],
    flake8_result: Tuple[bool, List[str]],
) -> str:
    """
    Generate concise formatting report

    Args:
        files: List of formatted files
        black_result: (success, message) from Black
        isort_result: (success, message) from isort
        flake8_result: (success, error_lines) from Flake8

    Returns:
        Formatted report string
    """
    black_success, _ = black_result
    isort_success, _ = isort_result
    flake8_success, flake8_errors = flake8_result

    # Build status icons
    black_status = "✓" if black_success else "✗"
    isort_status = "✓" if isort_success else "✗"
    flake8_status = "✓" if flake8_success else "✗"

    # Single line summary
    summary = f"🎨 Formatted {len(files)} file(s) | Black {black_status} | isort {isort_status} | Flake8 {flake8_status}"

    # If there are critical errors, show them
    if not flake8_success and flake8_errors:
        error_details = "\n".join([f"  {e}" for e in flake8_errors[:5]])
        if len(flake8_errors) > 5:
            error_details += f"\n  ... and {len(flake8_errors) - 5} more"
        return f"{summary}\n\n❌ Critical errors found:\n{error_details}"

    return summary


# ============================================================================
# Main Logic
# ============================================================================


def main():
    """Main entry point"""
    # Debug: Log that hook was invoked
    try:
        with open(DEBUG_LOG, "a") as f:
            f.write(f"[{datetime.datetime.now()}] Stop hook invoked\n")
    except Exception:
        pass

    # Load input
    input_data = load_input()

    # Prevent infinite loops (if Stop hook triggers another Stop hook)
    if input_data.get("stop_hook_active"):
        sys.exit(0)

    # Get project directory
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())

    # Detect modified Python files
    files = get_modified_python_files(project_dir)

    # If no files to format, silent exit
    if not files:
        sys.exit(0)

    # Run formatters
    black_result = run_black(files, project_dir)
    isort_result = run_isort(files, project_dir)
    flake8_result = run_flake8(files, project_dir)

    # Generate report
    report = generate_report(files, black_result, isort_result, flake8_result)

    # Output as JSON (required for Stop Hook to display messages)
    output = {
        "systemMessage": report
    }
    print(json.dumps(output))

    # Always exit successfully (don't block Claude's workflow)
    sys.exit(0)


if __name__ == "__main__":
    main()
