"""Cross-platform source and distribution checks for AgentSecBench releases."""

from __future__ import annotations

import argparse
import ast
import hashlib
import re
import shlex
import stat
import sys
import tarfile
import tomllib
import zipfile
from collections.abc import Iterable, Sequence
from email.message import Message
from email.parser import Parser
from pathlib import Path, PurePosixPath
from typing import NoReturn, cast

PROJECT_NAME = "agentsecbench"
ROOT = Path(__file__).resolve().parents[1]
VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
CHANGELOG_PATTERN = re.compile(
    r"^## (?P<version>[0-9]+\.[0-9]+\.[0-9]+) - "
    r"(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})$",
    re.MULTILINE,
)
MARKDOWN_LINK_PATTERN = re.compile(r"(?<!!)\[[^]]+\]\((?P<target>[^)]+)\)")
EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)"
)
SYNTHETIC_EMAIL_DOMAINS = frozenset({"example.local", "evil.test"})
MAX_ARCHIVE_MEMBERS = 500
MAX_ARCHIVE_PATH_LENGTH = 512
MAX_UNPACKED_BYTES = 20_000_000
REQUIRED_PROJECT_FILES = (
    "CITATION.cff",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "agentsecbench-threat-model.md",
    ".github/ISSUE_TEMPLATE/benchmark_proposal.yml",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    "docs/PUBLICATION_CHECKLIST.md",
    "docs/SHOWCASE.md",
    "examples/showcase/manifest.json",
    "examples/showcase/secure.result.json",
    "examples/showcase/unsafe.result.json",
    "pyproject.toml",
    "scripts/showcase.py",
    "src/agentsecbench/py.typed",
    "uv.lock",
)


class ReleaseGateError(RuntimeError):
    """Raised when release evidence is absent or inconsistent."""


def _fail(message: str) -> NoReturn:
    raise ReleaseGateError(message)


def _read_text(relative_path: str) -> str:
    path = ROOT / relative_path
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ReleaseGateError(f"cannot read required file: {relative_path}") from error


def project_version() -> str:
    """Return the exact PEP 621 project version."""

    try:
        document = tomllib.loads(_read_text("pyproject.toml"))
        project = cast(dict[str, object], document["project"])
        version = project["version"]
    except (KeyError, TypeError) as error:
        raise ReleaseGateError("pyproject project version is unavailable") from error
    if not isinstance(version, str) or VERSION_PATTERN.fullmatch(version) is None:
        _fail("pyproject project version is not an exact semantic version")
    return version


def package_version() -> str:
    """Read ``__version__`` without importing the package under test."""

    try:
        module = ast.parse(_read_text("src/agentsecbench/__init__.py"))
    except SyntaxError as error:
        raise ReleaseGateError("package initializer cannot be parsed") from error
    for statement in module.body:
        if not isinstance(statement, ast.Assign) or len(statement.targets) != 1:
            continue
        target = statement.targets[0]
        if (
            isinstance(target, ast.Name)
            and target.id == "__version__"
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            return statement.value.value
    _fail("package __version__ is unavailable")


def _check_required_files() -> None:
    missing = [relative for relative in REQUIRED_PROJECT_FILES if not (ROOT / relative).is_file()]
    if missing:
        _fail(f"required project file is missing: {missing[0]}")


def _check_changelog(version: str) -> str:
    match = CHANGELOG_PATTERN.search(_read_text("CHANGELOG.md"))
    if match is None or match.group("version") != version:
        _fail("the first changelog release does not match the project version")
    return match.group("date")


def _check_citation(version: str, release_date: str) -> None:
    fields: dict[str, str] = {}
    for line in _read_text("CITATION.cff").splitlines():
        if not line or line[0].isspace() or ":" not in line:
            continue
        key, value = line.split(":", maxsplit=1)
        fields[key] = value.strip().strip('"')
    expected = {
        "cff-version": "1.2.0",
        "type": "software",
        "repository-code": "https://github.com/zheyuanhu2-sketch/agentsecbench",
        "version": version,
        "date-released": release_date,
        "license": "MIT",
    }
    if any(fields.get(key) != value for key, value in expected.items()):
        _fail("citation metadata does not match the release contract")


def _markdown_files() -> tuple[Path, ...]:
    top_level = tuple(ROOT.glob("*.md"))
    documentation = tuple((ROOT / "docs").glob("*.md"))
    return tuple(sorted((*top_level, *documentation)))


def _check_local_markdown_links() -> None:
    for document in _markdown_files():
        text = document.read_text(encoding="utf-8")
        for match in MARKDOWN_LINK_PATTERN.finditer(text):
            target = match.group("target").split("#", maxsplit=1)[0]
            if not target or target.startswith(("https://", "http://", "mailto:")):
                continue
            resolved = (document.parent / target).resolve()
            try:
                resolved.relative_to(ROOT)
            except ValueError:
                _fail(f"Markdown link leaves the repository: {document.relative_to(ROOT)}")
            if not resolved.exists():
                relative_document = document.relative_to(ROOT).as_posix()
                _fail(f"broken local Markdown link in {relative_document}: {target}")


def _readme_commands() -> tuple[str, ...]:
    prefix = "uv run agentsecbench "
    commands: list[str] = []
    pending = ""
    for raw_line in _read_text("README.md").splitlines():
        line = raw_line.strip()
        if not pending and not line.startswith(prefix):
            continue
        pending = f"{pending} {line}" if pending else line
        if pending.endswith("`"):
            pending = pending[:-1].rstrip()
            continue
        commands.append(pending.removeprefix(prefix))
        pending = ""
    if pending:
        _fail("README contains an incomplete continued command")
    return tuple(commands)


def _check_readme_commands() -> None:
    from agentsecbench.cli import _build_parser

    documented = _readme_commands()
    if not documented:
        _fail("README contains no executable AgentSecBench commands")
    parser = _build_parser()
    for command in documented:
        try:
            parser.parse_args(shlex.split(command, posix=True))
        except (SystemExit, ValueError) as error:
            raise ReleaseGateError(f"README command does not match the CLI: {command}") from error


def _check_synthetic_catalogs() -> None:
    from agentsecbench.catalog import build_catalog
    from agentsecbench.scenario_io import load_scenario_catalog

    catalogs = (
        build_catalog(),
        load_scenario_catalog(ROOT / "examples" / "scenario-catalog-v1.json"),
    )
    for catalog in catalogs:
        for scenario in catalog:
            values = [scenario.goal, *scenario.sensitive_values]
            for message in scenario.messages:
                values.extend((message.sender, message.subject, message.body))
            for record in scenario.files:
                values.extend((record.path, record.content))
            for action in scenario.actions:
                values.extend(action.arguments.values())
            serialized = "\n".join(values)
            domains = {match.lower() for match in EMAIL_PATTERN.findall(serialized)}
            unexpected_domains = sorted(domains - SYNTHETIC_EMAIL_DOMAINS)
            if unexpected_domains:
                _fail(
                    f"scenario {scenario.task_id} contains a non-synthetic email domain: "
                    f"{unexpected_domains[0]}"
                )
            if any(not value.startswith("SYNTHETIC-") for value in scenario.sensitive_values):
                _fail(f"scenario {scenario.task_id} contains a non-synthetic sensitive value")


def check_source(*, expected_tag: str | None = None) -> str:
    """Validate source-level release invariants and return the version."""

    _check_required_files()
    version = project_version()
    if package_version() != version:
        _fail("package and project versions differ")
    if expected_tag is not None and expected_tag != f"v{version}":
        _fail("release tag does not match the project version")
    release_date = _check_changelog(version)
    _check_citation(version, release_date)
    _check_local_markdown_links()
    _check_readme_commands()
    _check_synthetic_catalogs()
    return version


def _safe_archive_names(names: Iterable[str], expected_roots: frozenset[str]) -> tuple[str, ...]:
    safe_names: list[str] = []
    seen: set[str] = set()
    for name in names:
        path = PurePosixPath(name)
        if (
            not name
            or len(name) > MAX_ARCHIVE_PATH_LENGTH
            or "\\" in name
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or path.parts[0] not in expected_roots
            or name in seen
        ):
            _fail("distribution contains an unsafe archive path")
        seen.add(name)
        safe_names.append(name)
        if len(safe_names) > MAX_ARCHIVE_MEMBERS:
            _fail("distribution contains too many archive members")
    return tuple(safe_names)


def _metadata_value(metadata: Message, key: str) -> str:
    value = metadata.get(key)
    if value is None:
        _fail(f"distribution metadata is missing {key}")
    return value


def _check_metadata(raw: str, version: str) -> None:
    metadata = Parser().parsestr(raw)
    expected = {
        "Name": PROJECT_NAME,
        "Version": version,
        "Summary": "A deterministic security benchmark for tool-using AI agents.",
        "Requires-Python": ">=3.11",
        "License-Expression": "MIT",
        "Description-Content-Type": "text/markdown",
    }
    for key, value in expected.items():
        if _metadata_value(metadata, key) != value:
            _fail(f"distribution metadata has an unexpected {key}")
    project_urls = set(cast(list[str], metadata.get_all("Project-URL", [])))
    expected_urls = {
        "Changelog, https://github.com/zheyuanhu2-sketch/agentsecbench/blob/main/CHANGELOG.md",
        "Issues, https://github.com/zheyuanhu2-sketch/agentsecbench/issues",
        "Repository, https://github.com/zheyuanhu2-sketch/agentsecbench",
    }
    if project_urls != expected_urls:
        _fail("distribution metadata has unexpected project URLs")
    classifiers = set(cast(list[str], metadata.get_all("Classifier", [])))
    required_classifiers = {
        "Development Status :: 5 - Production/Stable",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Typing :: Typed",
    }
    if not required_classifiers <= classifiers:
        _fail("distribution metadata is missing a required classifier")
    if metadata.get_all("Requires-Dist"):
        _fail("runtime distribution unexpectedly declares a dependency")


def _check_wheel(path: Path, version: str) -> None:
    distribution = f"{PROJECT_NAME}-{version}.dist-info"
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            names = _safe_archive_names(
                (member.filename for member in members),
                frozenset({PROJECT_NAME, distribution}),
            )
            if sum(member.file_size for member in members) > MAX_UNPACKED_BYTES:
                _fail("wheel exceeds the unpacked size limit")
            if any(stat.S_ISLNK(member.external_attr >> 16) for member in members):
                _fail("wheel contains a symbolic link")
            required = {
                f"{PROJECT_NAME}/__init__.py",
                f"{PROJECT_NAME}/cli.py",
                f"{PROJECT_NAME}/py.typed",
                f"{distribution}/METADATA",
                f"{distribution}/WHEEL",
                f"{distribution}/entry_points.txt",
                f"{distribution}/licenses/LICENSE",
                f"{distribution}/RECORD",
            }
            if not required <= set(names):
                _fail("wheel is missing required runtime or metadata files")
            if any(name.startswith(("tests/", "scripts/")) for name in names):
                _fail("wheel contains repository-only files")
            raw_metadata = archive.read(f"{distribution}/METADATA").decode("utf-8")
            entry_points = archive.read(f"{distribution}/entry_points.txt").decode("utf-8")
    except (OSError, UnicodeError, zipfile.BadZipFile, KeyError) as error:
        raise ReleaseGateError("wheel cannot be read") from error
    _check_metadata(raw_metadata, version)
    if entry_points.strip() != "[console_scripts]\nagentsecbench = agentsecbench.cli:main":
        _fail("wheel console entry point is invalid")


def _check_sdist(path: Path, version: str) -> None:
    prefix = f"{PROJECT_NAME}-{version}"
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
            names = _safe_archive_names((member.name for member in members), frozenset({prefix}))
            if sum(member.size for member in members) > MAX_UNPACKED_BYTES:
                _fail("source distribution exceeds the unpacked size limit")
            if any(not (member.isfile() or member.isdir()) for member in members):
                _fail("source distribution contains a non-file archive member")
            required = {
                f"{prefix}/LICENSE",
                f"{prefix}/CITATION.cff",
                f"{prefix}/.github/ISSUE_TEMPLATE/benchmark_proposal.yml",
                f"{prefix}/.github/ISSUE_TEMPLATE/bug_report.yml",
                f"{prefix}/.github/ISSUE_TEMPLATE/config.yml",
                f"{prefix}/README.md",
                f"{prefix}/SECURITY.md",
                f"{prefix}/PKG-INFO",
                f"{prefix}/docs/DATA_REVIEW.md",
                f"{prefix}/docs/RELEASE_PROCESS.md",
                f"{prefix}/docs/SHOWCASE.md",
                f"{prefix}/examples/showcase/manifest.json",
                f"{prefix}/examples/showcase/secure.result.json",
                f"{prefix}/examples/showcase/unsafe.result.json",
                f"{prefix}/pyproject.toml",
                f"{prefix}/scripts/release_gate.py",
                f"{prefix}/scripts/showcase.py",
                f"{prefix}/src/agentsecbench/__init__.py",
                f"{prefix}/src/agentsecbench/py.typed",
                f"{prefix}/tests/test_catalog.py",
            }
            if not required <= set(names):
                _fail("source distribution is missing required source or review files")
            member = archive.extractfile(f"{prefix}/PKG-INFO")
            if member is None:
                _fail("source distribution metadata cannot be read")
            raw_metadata = member.read().decode("utf-8")
    except (OSError, UnicodeError, tarfile.TarError, KeyError) as error:
        raise ReleaseGateError("source distribution cannot be read") from error
    _check_metadata(raw_metadata, version)


def distribution_paths(directory: Path, version: str) -> tuple[Path, Path]:
    """Return the exact wheel and sdist paths, rejecting stale package outputs."""

    wheel = directory / f"{PROJECT_NAME}-{version}-py3-none-any.whl"
    sdist = directory / f"{PROJECT_NAME}-{version}.tar.gz"
    if not directory.is_dir() or not wheel.is_file() or not sdist.is_file():
        _fail("distribution directory does not contain the expected wheel and sdist")
    unexpected = sorted(
        path.name
        for path in directory.iterdir()
        if path.is_file() and path.suffix in {".whl", ".gz"} and path not in {wheel, sdist}
    )
    if unexpected:
        _fail(f"distribution directory contains a stale package: {unexpected[0]}")
    return wheel, sdist


def check_artifacts(directory: Path) -> tuple[Path, Path]:
    """Validate built package structure and metadata."""

    version = check_source()
    wheel, sdist = distribution_paths(directory, version)
    _check_wheel(wheel, version)
    _check_sdist(sdist, version)
    return wheel, sdist


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compare_builds(first: Path, second: Path) -> None:
    """Require two independently built distribution sets to be byte-identical."""

    version = check_source()
    first_paths = distribution_paths(first, version)
    second_paths = distribution_paths(second, version)
    for left, right in zip(first_paths, second_paths, strict=True):
        if left.name != right.name or _sha256(left) != _sha256(right):
            _fail(f"repeated build is not reproducible: {left.name}")


def write_checksums(directory: Path, output: Path) -> None:
    """Write canonical SHA-256 checksums for validated release packages."""

    packages = check_artifacts(directory)
    lines = [
        f"{_sha256(path)}  {path.name}\n" for path in sorted(packages, key=lambda item: item.name)
    ]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("".join(lines), encoding="ascii", newline="\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    source = subparsers.add_parser("source", help="Validate source release invariants.")
    source.add_argument("--tag", help="Require an exact v<version> release tag.")
    artifacts = subparsers.add_parser("artifacts", help="Validate a built wheel and sdist.")
    artifacts.add_argument("directory", type=Path)
    compare = subparsers.add_parser("compare", help="Compare two independent builds.")
    compare.add_argument("first", type=Path)
    compare.add_argument("second", type=Path)
    checksums = subparsers.add_parser("checksums", help="Write canonical SHA-256 checksums.")
    checksums.add_argument("directory", type=Path)
    checksums.add_argument("output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "source":
            version = check_source(expected_tag=args.tag)
            print(f"Source release invariants passed for {PROJECT_NAME} {version}.")
        elif args.command == "artifacts":
            check_artifacts(args.directory)
            print("Distribution structure and metadata passed.")
        elif args.command == "compare":
            compare_builds(args.first, args.second)
            print("Repeated builds are byte-identical.")
        else:
            write_checksums(args.directory, args.output)
            print("Canonical SHA-256 checksums written.")
    except ReleaseGateError as error:
        print(f"Release gate failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
