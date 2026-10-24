"""Bounded static product-source policy; never imports/executes the application.

Development evaluation/provider/scanner/release harnesses are outside scope.
A clear AST result cannot establish
runtime effects, dependency behavior, sandboxing or independent product acceptance.
"""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import sys

MAX_FILES = 64
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024
MAX_NODES = 100_000
MAX_ENTRIES = 512
MAX_DIRECTORY_DEPTH = 8
BLOCKED_IMPORTS = (
    "socket", "_socket", "socketserver", "http", "urllib", "urllib3", "requests", "httpx", "aiohttp",
    "subprocess", "asyncio", "multiprocessing", "boto3", "botocore", "azure", "google.cloud",
    "openai", "anthropic", "grpc", "paramiko", "ftplib", "smtplib", "telnetlib", "xmlrpc",
    "webbrowser", "ctypes", "cffi", "keyring", "eval", "scripts", "tests",
)
BLOCKED_CALLS = {
    "__import__", "builtins.__import__", "eval", "exec", "compile", "builtins.eval",
    "builtins.exec", "builtins.compile", "importlib.import_module", "importlib.util.module_from_spec",
    "os.system", "os.popen", "os.startfile", "os.fork", "os.forkpty",
    "concurrent.futures.ProcessPoolExecutor",
    "os.getenv", "os.getenvb", "os.environ.get", "os.environb.get",
}
DECLARATIVE_CALLS = {
    "frozenset", "set", "dict", "tuple", "list", "object", "re.compile",
    "pydantic.Field", "pydantic.ConfigDict", "pydantic.field_validator", "pydantic.model_validator",
    "dataclasses.field", "dataclasses.dataclass",
}
DECORATORS = DECLARATIVE_CALLS | {"staticmethod", "classmethod", "property"}


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _name(node.value)
        return f"{parent}.{node.attr}" if parent else ""
    return ""


def _qualified(node: ast.AST, aliases: dict[str, str]) -> str:
    name = _name(node)
    first, dot, rest = name.partition(".")
    return aliases.get(first, first) + (dot + rest if dot else "")


def _blocked(name: str) -> bool:
    return any(name == prefix or name.startswith(prefix + ".") for prefix in BLOCKED_IMPORTS)


def _main_guard(node: ast.If) -> bool:
    test = node.test
    return (
        isinstance(test, ast.Compare) and isinstance(test.left, ast.Name)
        and test.left.id == "__name__" and len(test.ops) == len(test.comparators) == 1
        and isinstance(test.ops[0], ast.Eq) and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value == "__main__"
    )


def _declarations(body: list[ast.stmt], aliases: dict[str, str], issue) -> None:
    def expression(node):
        if node is not None:
            for child in ast.walk(node):
                if isinstance(child, ast.Call) and _qualified(child.func, aliases) not in DECLARATIVE_CALLS:
                    issue(child, "import_time_call")
                if isinstance(child, (ast.Await, ast.Yield, ast.YieldFrom, ast.NamedExpr,
                                      ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                    issue(child, "import_time_expression")

    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Pass)):
            continue
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(not isinstance(target, ast.Name) for target in targets):
                issue(node, "import_time_mutation")
            expression(node.value)
            if isinstance(node, ast.AnnAssign):
                expression(node.annotation)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for decorator in node.decorator_list:
                target = decorator.func if isinstance(decorator, ast.Call) else decorator
                if _qualified(target, aliases) not in DECORATORS:
                    issue(decorator, "unknown_decorator")
                expression(decorator)
            if isinstance(node, ast.ClassDef):
                for value in (*node.bases, *(keyword.value for keyword in node.keywords)):
                    expression(value)
                _declarations(node.body, aliases, issue)
            else:
                for value in (*node.args.defaults, *node.args.kw_defaults, node.returns):
                    expression(value)
                for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
                    expression(argument.annotation)
        elif isinstance(node, ast.If) and _main_guard(node):
            _declarations(node.orelse, aliases, issue)
        else:
            issue(node, "import_time_statement")


def _source_paths(package: Path, issue):
    todo = [(package, 0)]
    count = 0
    while todo:
        directory, depth = todo.pop()
        if depth > MAX_DIRECTORY_DEPTH:
            issue("iac_review", None, "source_directory_depth_limit")
            return
        try:
            with_entries = []
            for path in directory.iterdir():
                count += 1
                if count > MAX_ENTRIES:
                    issue("iac_review", None, "source_entry_limit")
                    return
                with_entries.append(path)
            for path in sorted(with_entries):
                if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
                    issue("iac_review", None, "source_link_rejected")
                elif path.is_dir():
                    todo.append((path, depth + 1))
                elif path.suffix == ".py":
                    yield path
        except OSError:
            issue("iac_review", None, "source_directory_unreadable")


def inspect_package(package: Path) -> dict:
    """Read only this product package; bounded syntax/import graph, no code loading."""
    package = Path(package).absolute()
    issues = []
    trees: dict[str, ast.Module] = {}
    package_modules = set()
    edges: dict[str, set[str]] = {}

    def add(module, node, code):
        issues.append({"module": module, "line": getattr(node, "lineno", 0), "code": code})

    if (package.name != "iac_review" or not package.is_dir()
            or any(path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())
                   for path in (package, *package.parents))):
        add("iac_review", None, "product_package_required")
    else:
        total_bytes = 0
        for index, path in enumerate(_source_paths(package, add)):
            if index >= MAX_FILES:
                add("iac_review", None, "source_file_limit")
                break
            relative = path.relative_to(package)
            parts = list(relative.with_suffix("").parts)
            is_package = parts[-1] == "__init__"
            if is_package:
                parts.pop()
            module = ".".join(("iac_review", *parts))
            try:
                if any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction())
                       for p in (path, *path.parents)):
                    add(module, None, "source_link_rejected")
                    continue
                with path.open("rb") as stream:
                    data = stream.read(MAX_FILE_BYTES + 1)
                total_bytes += len(data)
                if len(data) > MAX_FILE_BYTES or total_bytes > MAX_TOTAL_BYTES:
                    add(module, None, "source_byte_limit")
                    break
                tree = ast.parse(data.decode("utf-8"), filename=str(relative))
                if sum(1 for _ in ast.walk(tree)) > MAX_NODES:
                    add(module, None, "source_node_limit")
                    continue
                trees[module] = tree
                if is_package:
                    package_modules.add(module)
            except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError):
                add(module, None, "source_unreadable_or_invalid")

    for module, tree in trees.items():
        aliases: dict[str, str] = {}
        imports = []
        edges[module] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append((node, alias.name))
                    aliases[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ""
                if node.level:
                    parent = module if module in package_modules else module.rsplit(".", 1)[0]
                    parts = parent.split(".")
                    if node.level > len(parts):
                        add(module, node, "relative_import_escape")
                        continue
                    base = ".".join((*parts[:len(parts) - node.level + 1], *([base] if base else [])))
                imports.append((node, base))
                for alias in node.names:
                    qualified = f"{base}.{alias.name}"
                    aliases[alias.asname or alias.name] = qualified
                    if qualified in trees:
                        edges[module].add(qualified)
        for node, target in imports:
            if _blocked(target):
                add(module, node, "forbidden_import")
            root = target.split(".")[0]
            if root == "iac_review":
                if target not in trees:
                    add(module, node, "missing_product_module")
                else:
                    edges[module].add(target)
                    if target != "iac_review" and "iac_review" in trees:
                        edges[module].add("iac_review")
            elif root not in sys.stdlib_module_names | {"pydantic", "__future__"}:
                add(module, node, "unapproved_dependency_import")
        for node in ast.walk(tree):
            if isinstance(node, (ast.Name, ast.Attribute)) and _qualified(node, aliases) in {
                    "os.environ", "os.environb"}:
                add(module, node, "product_environment_access")
            if isinstance(node, ast.Call):
                target = _qualified(node.func, aliases)
                if (target in BLOCKED_CALLS or _blocked(target)
                        or target.startswith(("os.spawn", "os.exec", "os.posix_spawn"))):
                    add(module, node, "forbidden_or_dynamic_call")
        # __main__ is an intentional command entrypoint, not a default import.
        if module != "iac_review.__main__":
            _declarations(tree.body, aliases, lambda node, code: add(module, node, code))

    roots = {"iac_review", "iac_review.cli"}
    for missing in roots - trees.keys():
        add(missing, None, "default_root_missing")
    reachable = set()
    todo = list(roots & trees.keys())
    while todo:
        module = todo.pop()
        if module not in reachable:
            reachable.add(module)
            todo.extend(edges.get(module, set()) - reachable)
    return {
        "status": "static_source_policy_clear" if not issues else "static_source_policy_findings",
        "modules_read": len(trees), "default_import_roots": sorted(roots),
        "default_reachable_modules": sorted(reachable),
        "import_edges": {name: sorted(targets) for name, targets in sorted(edges.items())},
        "issues": sorted(issues, key=lambda row: (row["module"], row["line"], row["code"])),
        "runtime_verified": False, "dependency_behavior_verified": False,
        "development_evaluation_inspected": False,
        "authorization_granted": False, "publication_performed": False,
        "limitations": [
            "Product package source only; evaluation/provider/scanner/edition harnesses excluded.",
            "Default product environment/credential lookup is a finding; external approval is not inferred.",
            "Graph includes syntactic lazy imports; closure is not an observed module-load inventory.",
            "__main__ is excluded from import-time declaration checks, not import/call checks.",
            "Declarative dataclass/Pydantic/re calls are trusted syntax, not audited dependency behavior.",
            "Aliases/rebinding/reflection/generated or native code can defeat static inference.",
            "Static policy is not an effect sandbox, execution evidence or product acceptance.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path,
                        default=Path(__file__).resolve().parents[1] / "src" / "iac_review")
    args = parser.parse_args(argv)
    report = inspect_package(args.package)
    sys.stdout.write(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return 0 if not report["issues"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
