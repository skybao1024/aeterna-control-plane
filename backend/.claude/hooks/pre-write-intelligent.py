#!/usr/bin/env python3
"""
Intelligent Pre-Write Hook - Smart Code Duplication Detection

Core Features:
1. AST Structure Analysis - Understand code's true responsibilities
2. Similarity Scoring - Multi-dimensional evaluation (structure/function/semantics)
3. Architecture Awareness - Understand file's role in the project
4. Intelligent Thresholds - Dynamic alert level adjustment

Input: JSON via stdin
Output: JSON via stdout + exit code
"""

import ast
import json
import os
import re
import subprocess
import sys
from difflib import SequenceMatcher
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Try to load .env file (if exists)
try:
    from dotenv import load_dotenv

    # Load .env file from project root
    env_path = Path(__file__).parent.parent.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    # python-dotenv not installed, skip
    pass

# ============================================================================
# Configuration
# ============================================================================

# Similarity thresholds (0-100)
SIMILARITY_THRESHOLDS = {
    "service": 60,  # Service layer: Lower threshold to catch exact copies
    "model": 55,  # Model layer: Correspondingly lower
    "api": 45,  # API layer: Loose check, endpoints may be similar
    "util": 65,  # Utility classes: Relatively strict
    "schema": 45,  # Schema: Loose check, DTOs may be similar
    "default": 60,  # Default threshold lowered
}

# Keyword weights (affects similarity calculation, should sum to 1.0)
KEYWORD_WEIGHTS = {
    "class_name": 0.20,  # Class name similarity (lower weight)
    "method_names": 0.25,  # Method name similarity (higher weight, better indicates functionality)
    "imports": 0.15,  # Import dependency similarity
    "decorators": 0.10,  # Decorator similarity
    "base_classes": 0.15,  # Inheritance relationship similarity
    "function_names": 0.15,  # Function name similarity
}

# File size limit (avoid memory issues)
MAX_FILE_SIZE_MB = 5  # Maximum 5MB

# Performance configuration
FIND_TIMEOUT = 5  # find command timeout (seconds)
MAX_CANDIDATE_FILES = 30  # Maximum number of candidate files to analyze


# ============================================================================
# Utility Functions
# ============================================================================


def load_input():
    """Load JSON input from stdin"""
    try:
        return json.load(sys.stdin)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
        sys.exit(1)


def detect_file_role(file_path: str) -> str:
    """
    Detect file's role in the project architecture

    Returns:
        "service" | "model" | "api" | "util" | "schema" | "unknown"
    """
    path_lower = file_path.lower()

    if "/services/" in path_lower:
        return "service"
    elif "/models/" in path_lower:
        return "model"
    elif "/api/" in path_lower or "/route/" in path_lower:
        return "api"
    elif "/schemas/" in path_lower:
        return "schema"
    elif "/utils/" in path_lower or "/core/" in path_lower:
        return "util"
    else:
        return "unknown"


# ============================================================================
# AST Code Analysis
# ============================================================================


class CodeAnalyzer(ast.NodeVisitor):
    """AST Code Analyzer - Extract code structure features"""

    def __init__(self):
        self.classes: List[Dict] = []
        self.functions: List[str] = []
        self.imports: Set[str] = set()
        self.decorators: Set[str] = set()

    def visit_ClassDef(self, node):
        """Extract class definition information"""
        class_info = {
            "name": node.name,
            "methods": [m.name for m in node.body if isinstance(m, ast.FunctionDef)],
            "base_classes": [self._get_base_name(base) for base in node.bases],
            "decorators": [self._get_decorator_name(d) for d in node.decorator_list],
        }
        self.classes.append(class_info)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        """Extract top-level functions"""
        # Note: This method is called for all functions (including class methods)
        # By checking parent nodes to determine if it's a top-level function
        # Since visit is called recursively, class methods are handled separately in visit_ClassDef
        # Here we only record decorator information, top-level function detection is handled after visit completes

        # Collect decorators
        for decorator in node.decorator_list:
            self.decorators.add(self._get_decorator_name(decorator))

        self.generic_visit(node)

    def visit_Import(self, node):
        """Extract import statements"""
        for alias in node.names:
            self.imports.add(alias.name.split(".")[0])

    def visit_ImportFrom(self, node):
        """Extract from ... import statements"""
        if node.module:
            self.imports.add(node.module.split(".")[0])

    def _get_base_name(self, base) -> str:
        """Get base class name"""
        if isinstance(base, ast.Name):
            return base.id
        elif isinstance(base, ast.Attribute):
            return base.attr
        return ""

    def _get_decorator_name(self, decorator) -> str:
        """Get decorator name"""
        if isinstance(decorator, ast.Name):
            return decorator.id
        elif isinstance(decorator, ast.Attribute):
            return decorator.attr
        elif isinstance(decorator, ast.Call):
            if isinstance(decorator.func, ast.Name):
                return decorator.func.id
            elif isinstance(decorator.func, ast.Attribute):
                return decorator.func.attr
        return ""


def analyze_code(content: str) -> Optional[CodeAnalyzer]:
    """
    Analyze code structure

    Returns:
        CodeAnalyzer object, or None if parsing fails
    """
    try:
        tree = ast.parse(content)
        analyzer = CodeAnalyzer()
        analyzer.visit(tree)

        # Extract top-level functions (functions not in any class)
        class_methods = set()
        for cls in analyzer.classes:
            class_methods.update(cls["methods"])

        # Traverse AST root nodes to find top-level functions
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                if node.name not in class_methods:
                    analyzer.functions.append(node.name)

        return analyzer
    except SyntaxError:
        return None
    except Exception as e:
        print(f"Warning: Failed to parse code: {e}", file=sys.stderr)
        return None


# ============================================================================
# Similarity Calculation
# ============================================================================


def calculate_string_similarity(str1: str, str2: str) -> float:
    """
    Calculate similarity between two strings (0-1)

    Uses SequenceMatcher algorithm
    """
    return SequenceMatcher(None, str1.lower(), str2.lower()).ratio()


def calculate_set_similarity(set1: Set[str], set2: Set[str]) -> float:
    """
    Calculate Jaccard similarity between two sets (0-1)

    Jaccard = |A ∩ B| / |A ∪ B|
    """
    if not set1 and not set2:
        return 0.0
    if not set1 or not set2:
        return 0.0

    intersection = len(set1 & set2)
    union = len(set1 | set2)
    return intersection / union if union > 0 else 0.0


def calculate_code_similarity(
    analyzer1: CodeAnalyzer, analyzer2: CodeAnalyzer
) -> Tuple[float, Dict[str, float]]:
    """
    Calculate similarity between two code files (0-100)

    Returns:
        (total similarity score, dimension scores details)
    """
    scores = {}

    # 1. Class name similarity
    class_names1 = set([c["name"] for c in analyzer1.classes])
    class_names2 = set([c["name"] for c in analyzer2.classes])
    scores["class_name"] = calculate_set_similarity(class_names1, class_names2)

    # 2. Method name similarity (merge all methods from all classes)
    all_methods1 = set()
    all_methods2 = set()
    for cls in analyzer1.classes:
        all_methods1.update(cls["methods"])
    for cls in analyzer2.classes:
        all_methods2.update(cls["methods"])
    scores["method_names"] = calculate_set_similarity(all_methods1, all_methods2)

    # 3. Import dependency similarity
    scores["imports"] = calculate_set_similarity(analyzer1.imports, analyzer2.imports)

    # 4. Decorator similarity
    scores["decorators"] = calculate_set_similarity(
        analyzer1.decorators, analyzer2.decorators
    )

    # 5. Inheritance relationship similarity
    base_classes1 = set()
    base_classes2 = set()
    for cls in analyzer1.classes:
        base_classes1.update(cls["base_classes"])
    for cls in analyzer2.classes:
        base_classes2.update(cls["base_classes"])
    scores["base_classes"] = calculate_set_similarity(base_classes1, base_classes2)

    # 6. Top-level function name similarity
    scores["function_names"] = calculate_set_similarity(
        set(analyzer1.functions), set(analyzer2.functions)
    )

    # Weighted total score calculation
    total_score = sum(
        scores.get(key, 0) * weight for key, weight in KEYWORD_WEIGHTS.items()
    )

    return total_score * 100, scores  # Convert to 0-100 score


# ============================================================================
# Intelligent File Search
# ============================================================================


def find_similar_files(file_path: str, project_dir: str, file_role: str) -> List[str]:
    """
    Intelligently search for potentially similar files

    Strategy:
    1. Prioritize searching files in the same architectural layer (service/model/api)
    2. Exclude test files, migration files, etc.
    3. Limit search scope to avoid performance issues
    """
    search_paths = []

    # Determine search paths based on file role
    if file_role == "service":
        search_paths = [f"{project_dir}/app/services"]
    elif file_role == "model":
        search_paths = [f"{project_dir}/app/models"]
    elif file_role == "api":
        search_paths = [f"{project_dir}/app/api"]
    elif file_role == "schema":
        search_paths = [f"{project_dir}/app/schemas"]
    elif file_role == "util":
        search_paths = [f"{project_dir}/app/core", f"{project_dir}/app/utils"]
    else:
        # Unknown role, search entire app directory
        search_paths = [f"{project_dir}/app"]

    # Search for Python files
    candidate_files = []
    for search_path in search_paths:
        if not os.path.exists(search_path):
            continue

        try:
            result = subprocess.run(
                [
                    "find",
                    search_path,
                    "-type",
                    "f",
                    "-name",
                    "*.py",
                    "-not",
                    "-path",
                    "*/venv/*",
                    "-not",
                    "-path",
                    "*/__pycache__/*",
                    "-not",
                    "-path",
                    "*/test_*",
                    "-not",
                    "-path",
                    "*/migrations/*",
                ],
                capture_output=True,
                text=True,
                timeout=FIND_TIMEOUT,
            )

            if result.returncode == 0:
                files = [
                    f.strip()
                    for f in result.stdout.split("\n")
                    if f.strip() and f.strip() != file_path
                ]
                candidate_files.extend(files)
        except subprocess.TimeoutExpired:
            print(
                f"Warning: Find command timed out in {search_path} after {FIND_TIMEOUT}s",
                file=sys.stderr,
            )
        except Exception as e:
            print(
                f"Warning: Failed to search in {search_path}: {type(e).__name__}: {e}",
                file=sys.stderr,
            )

    # Limit search quantity to avoid analyzing too many files
    return candidate_files[:MAX_CANDIDATE_FILES]


# ============================================================================
# Main Detection Logic
# ============================================================================


def detect_code_duplication(
    file_path: str, content: str, project_dir: str
) -> List[Dict]:
    """
    Intelligently detect code duplication

    Returns:
        Detection result list, each item contains:
        {
            "similar_file": str,
            "similarity_score": float,
            "threshold": float,
            "details": Dict
        }
    """
    # 1. Analyze current file
    analyzer = analyze_code(content)
    if not analyzer:
        # Parsing failed, skip check
        return []

    # 2. Determine file role and threshold
    file_role = detect_file_role(file_path)
    threshold = SIMILARITY_THRESHOLDS.get(file_role, SIMILARITY_THRESHOLDS["default"])

    # 3. Search for candidate files
    candidate_files = find_similar_files(file_path, project_dir, file_role)

    # 4. Compare similarity with each candidate
    results = []
    for candidate_file in candidate_files:
        try:
            # Check file size to avoid memory issues
            file_size = os.path.getsize(candidate_file)
            if file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
                print(
                    f"Warning: Skipping {candidate_file} - file too large ({file_size / 1024 / 1024:.1f}MB)",
                    file=sys.stderr,
                )
                continue

            with open(candidate_file, "r", encoding="utf-8") as f:
                candidate_content = f.read()

            # Analyze candidate file
            candidate_analyzer = analyze_code(candidate_content)
            if not candidate_analyzer:
                continue

            # Calculate similarity
            similarity_score, score_details = calculate_code_similarity(
                analyzer, candidate_analyzer
            )

            # If exceeds threshold, record result
            if similarity_score >= threshold:
                results.append(
                    {
                        "similar_file": candidate_file,
                        "similarity_score": similarity_score,
                        "threshold": threshold,
                        "details": score_details,
                    }
                )

        except UnicodeDecodeError:
            print(
                f"Warning: Skipping {candidate_file} - not a valid UTF-8 text file",
                file=sys.stderr,
            )
            continue
        except Exception as e:
            print(
                f"Warning: Failed to analyze {candidate_file}: {type(e).__name__}: {e}",
                file=sys.stderr,
            )
            continue

    # Sort by similarity, return top 3 most similar
    results.sort(key=lambda x: x["similarity_score"], reverse=True)
    return results[:3]


# ============================================================================
# Architecture Rule Validation (Reusing original logic)
# ============================================================================


def validate_architecture(file_path: str, content: str) -> List[Dict]:
    """Validate architecture rules (reusing original logic)"""
    violations = []

    # Rule 1: Core/Common layer cannot import Service layer
    if "app/core/" in file_path or "app/services/common/" in file_path:
        service_imports = re.findall(
            r"from app\.services\.(client|backoffice)", content
        )
        if service_imports:
            violations.append(
                {
                    "rule": "Layer Dependency",
                    "severity": "error",
                    "message": "Core/Common layer cannot import from Service layer",
                    "details": f'Found imports: {", ".join(set(service_imports))}',
                }
            )

    # Rule 2: Singleton pattern check
    singleton_patterns = [
        {
            "pattern": r"Redis\([^)]*host",
            "file": "app/services/common/redis.py",
            "type": "Redis",
        },
        {
            "pattern": r"create_async_engine\(",
            "file": "app/db/base.py",
            "type": "Database Engine",
        },
    ]

    for singleton in singleton_patterns:
        if re.search(singleton["pattern"], content) and not file_path.endswith(
            singleton["file"]
        ):
            violations.append(
                {
                    "rule": "Singleton Pattern",
                    "severity": "error",
                    "message": f"{singleton['type']} should only be created in {singleton['file']}",
                }
            )

    # Rule 3: Environment variable access
    if "os.getenv" in content or "os.environ" in content:
        if not file_path.endswith("app/core/config.py"):
            violations.append(
                {
                    "rule": "Configuration",
                    "severity": "warning",
                    "message": "Use settings from app.core.config instead",
                }
            )

    return violations


# ============================================================================
# Format Output
# ============================================================================


def format_output(
    duplications: List[Dict], violations: List[Dict], file_role: str
) -> Optional[str]:
    """Format detection results"""
    if not duplications and not violations:
        return None

    lines = ["🔍 Intelligent Pre-Write Analysis\n"]
    lines.append("═" * 60)

    # Code duplication detection
    if duplications:
        lines.append(f"\n📊 Code Similarity Analysis (Role: {file_role})")

        for idx, dup in enumerate(duplications, 1):
            score = dup["similarity_score"]
            threshold = dup["threshold"]
            similar_file = dup["similar_file"]

            # Similarity level
            if score >= 80:
                level = "🚨 Very High"
            elif score >= 70:
                level = "⚠️  High"
            else:
                level = "ℹ️  Moderate"

            lines.append(
                f"\n{idx}. {level} Similarity: {score:.1f}/100 (Threshold: {threshold})"
            )
            lines.append(f"   Similar to: {similar_file}")

            # Detailed scores
            details = dup["details"]
            lines.append("   Breakdown:")
            for key, value in details.items():
                if value > 0:
                    lines.append(f"     - {key}: {value*100:.0f}%")

        lines.append("\n💡 Recommendations:")
        lines.append("   1. Review existing code - Can you extend it instead?")
        lines.append("   2. If functionality differs, consider renaming for clarity")
        lines.append("   3. Consult @architecture-advisor if unsure")

    # Architecture violations
    if violations:
        lines.append("\n\n🚨 Architecture Rule Violations:")
        for violation in violations:
            icon = "❌" if violation["severity"] == "error" else "⚠️"
            lines.append(f"\n{icon} {violation['rule']}")
            lines.append(f"   {violation['message']}")
            if "details" in violation:
                lines.append(f"   Details: {violation['details']}")

    return "\n".join(lines)


# ============================================================================
# Main Function
# ============================================================================


def main():
    # Load input
    input_data = load_input()

    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    project_dir = input_data.get("cwd", os.getcwd())

    # Only check Write and Edit tools
    if tool_name not in ["Write", "Edit"]:
        sys.exit(0)

    file_path = tool_input.get("file_path", "")
    content = tool_input.get("content", "") or tool_input.get("new_string", "")

    # Only check Python files
    if not file_path.endswith(".py"):
        sys.exit(0)

    # Exclude virtual environments, cache, hooks themselves
    exclude_patterns = [
        "/venv/",
        "/env/",
        "/.venv/",
        "/__pycache__/",
        "/site-packages/",
        "/.claude/hooks/",
        "/migrations/",  # Exclude migration files
        "/test_",  # Exclude test files
    ]
    if any(pattern in file_path for pattern in exclude_patterns):
        sys.exit(0)

    # 1. Intelligent code duplication detection
    duplications = detect_code_duplication(file_path, content, project_dir)

    # 2. Architecture rule validation
    violations = validate_architecture(file_path, content)

    # 3. Format output
    file_role = detect_file_role(file_path)
    message = format_output(duplications, violations, file_role)

    if message:
        # Check for critical issues
        has_errors = any(v["severity"] == "error" for v in violations)
        has_high_similarity = any(d["similarity_score"] >= 80 for d in duplications)

        if has_errors or has_high_similarity:
            # Block write, request user confirmation
            output = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": message,
                }
            }
            print(json.dumps(output), file=sys.stdout)
            sys.exit(1)  # Non-zero exit code indicates user confirmation needed
        else:
            # Only warnings, show message but allow write
            output = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "displayText": message,
                }
            }
            print(json.dumps(output), file=sys.stdout)
            sys.exit(0)

    # No issues, allow write silently
    sys.exit(0)


if __name__ == "__main__":
    main()
