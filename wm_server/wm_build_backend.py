from __future__ import annotations

import base64
import hashlib
import os
import re
import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

try:  # Python 3.11+
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover - Python <3.11
    try:
        import tomli as tomllib  # type: ignore
    except ModuleNotFoundError:  # pragma: no cover - fallback to pip's vendored tomli
        import pip._vendor.tomli as tomllib  # type: ignore


DIST_TAG = "py3-none-any"


@dataclass
class ProjectInfo:
    name: str
    version: str
    description: Optional[str]
    requires_python: Optional[str]
    dependencies: List[str]
    optional_dependencies: Dict[str, List[str]]
    scripts: Dict[str, str]
    readme_path: Optional[Path]
    authors: List[str]

    @property
    def dist_name(self) -> str:
        return self.name.replace("-", "_")

    @property
    def dist_info_name(self) -> str:
        return f"{self.dist_name}-{self.version}.dist-info"


def _load_project_info(project_root: Path) -> ProjectInfo:
    data = tomllib.loads(project_root.joinpath("pyproject.toml").read_text(encoding="utf-8"))
    project = data.get("project") or {}
    name = project.get("name")
    version = project.get("version")
    if not name or not version:
        raise RuntimeError("pyproject.toml must define [project] name and version")

    readme_raw = project.get("readme")
    readme_path = None
    if isinstance(readme_raw, str):
        maybe = project_root / readme_raw
        readme_path = maybe if maybe.is_file() else None
    elif isinstance(readme_raw, dict):
        file_name = readme_raw.get("file")
        if isinstance(file_name, str):
            maybe = project_root / file_name
            readme_path = maybe if maybe.is_file() else None

    authors: List[str] = []
    for entry in project.get("authors") or []:
        if isinstance(entry, dict):
            if "name" in entry:
                authors.append(entry["name"])

    return ProjectInfo(
        name=name,
        version=str(version),
        description=project.get("description"),
        requires_python=project.get("requires-python"),
        dependencies=list(project.get("dependencies") or []),
        optional_dependencies={
            key: list(value or [])
            for key, value in (project.get("optional-dependencies") or {}).items()
        },
        scripts=dict(project.get("scripts") or {}),
        readme_path=readme_path,
        authors=authors,
    )


class _Builder:
    def __init__(self, project_dir: Path):
        self.project_dir = project_dir
        self.info = _load_project_info(project_dir)
        self.src_dir = project_dir / "src"
        if not self.src_dir.exists():
            raise RuntimeError("Source tree must be located under ./src")

    def get_requires_for_build(self) -> List[str]:
        return []

    # ---------------- Wheel helpers ---------------- #
    def build_wheel(self, wheel_directory: str) -> str:
        wheel_dir = Path(wheel_directory)
        wheel_dir.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory() as tmp:
            build_root = Path(tmp)
            self._copy_sources(build_root)

            dist_info_dir = build_root / self.info.dist_info_name
            dist_info_dir.mkdir()
            self._write_metadata(dist_info_dir)
            self._write_wheel_file(dist_info_dir)
            if self.info.scripts:
                self._write_entry_points(dist_info_dir)

            record_rel = Path(self.info.dist_info_name) / "RECORD"
            record_path = dist_info_dir / "RECORD"
            records = self._build_records(build_root, exclude={record_rel})
            record_path.write_text("\n".join(records + [f"{record_rel.as_posix()},,"]) + "\n", encoding="utf-8")

            wheel_name = f"{self.info.dist_name}-{self.info.version}-{DIST_TAG}.whl"
            wheel_path = wheel_dir / wheel_name
            with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for file_path in build_root.rglob("*"):
                    if file_path.is_file():
                        rel = file_path.relative_to(build_root)
                        zf.write(file_path, rel.as_posix())
            return wheel_name

    def prepare_metadata(self, metadata_directory: str) -> str:
        target = Path(metadata_directory) / self.info.dist_info_name
        target.mkdir(parents=True, exist_ok=True)
        self._write_metadata(target)
        self._write_wheel_file(target)
        if self.info.scripts:
            self._write_entry_points(target)
        return self.info.dist_info_name

    # ---------------- sdist helpers ---------------- #
    def build_sdist(self, sdist_directory: str) -> str:
        sdist_dir = Path(sdist_directory)
        sdist_dir.mkdir(parents=True, exist_ok=True)
        archive_name = f"{self.info.dist_name}-{self.info.version}"
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp) / archive_name
            temp_root.mkdir()
            # Required files
            self._copy_file("pyproject.toml", temp_root / "pyproject.toml")
            self._copy_optional_file("README.md", temp_root / "README.md")
            self._copy_optional_file("requirements.txt", temp_root / "requirements.txt")
            self._copy_file("wm_build_backend.py", temp_root / "wm_build_backend.py")
            # Copy src tree
            shutil.copytree(self.src_dir, temp_root / "src")
            tar_path = sdist_dir / f"{archive_name}.tar.gz"
            with tarfile.open(tar_path, "w:gz") as tf:
                tf.add(temp_root, arcname=archive_name)
        return tar_path.name

    # ---------------- editable helpers ---------------- #
    def build_editable(self, wheel_directory: str) -> str:
        # Editable install implemented as a lightweight .pth-based wheel
        wheel_dir = Path(wheel_directory)
        wheel_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory() as tmp:
            build_root = Path(tmp)
            dist_info_dir = build_root / self.info.dist_info_name
            dist_info_dir.mkdir()
            self._write_metadata(dist_info_dir)
            self._write_wheel_file(dist_info_dir)
            if self.info.scripts:
                self._write_entry_points(dist_info_dir)

            pth_name = f"{self.info.dist_name}.pth"
            (build_root / pth_name).write_text(str(self.src_dir.resolve()), encoding="utf-8")
            record_rel = Path(self.info.dist_info_name) / "RECORD"
            record_path = dist_info_dir / "RECORD"
            records = self._build_records(build_root, exclude={record_rel})
            record_path.write_text("\n".join(records + [f"{record_rel.as_posix()},,"]) + "\n", encoding="utf-8")

            wheel_name = f"{self.info.dist_name}-{self.info.version}-editable.whl"
            wheel_path = wheel_dir / wheel_name
            with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for file_path in build_root.rglob("*"):
                    if file_path.is_file():
                        rel = file_path.relative_to(build_root)
                        zf.write(file_path, rel.as_posix())
            return wheel_name

    # ---------------- Internal utilities ---------------- #
    def _copy_sources(self, dest: Path) -> None:
        for item in self.src_dir.iterdir():
            target = dest / item.name
            if item.is_dir():
                shutil.copytree(item, target)
            else:
                shutil.copy2(item, target)

    def _copy_file(self, relative: str, dest: Path) -> None:
        src = self.project_dir / relative
        shutil.copy2(src, dest)

    def _copy_optional_file(self, relative: str, dest: Path) -> None:
        src = self.project_dir / relative
        if src.is_file():
            shutil.copy2(src, dest)

    def _write_metadata(self, target: Path) -> None:
        lines = ["Metadata-Version: 2.1", f"Name: {self.info.name}", f"Version: {self.info.version}"]
        if self.info.description:
            lines.append(f"Summary: {self.info.description}")
        for author in self.info.authors:
            lines.append(f"Author: {author}")
        if self.info.requires_python:
            lines.append(f"Requires-Python: {self.info.requires_python}")
        for dep in self.info.dependencies:
            lines.append(f"Requires-Dist: {dep}")
        for extra, deps in (self.info.optional_dependencies or {}).items():
            lines.append(f"Provides-Extra: {extra}")
            for dep in deps:
                lines.append(f"Requires-Dist: {dep}; extra == \"{extra}\"")

        readme_content = ""
        if self.info.readme_path:
            readme_content = self.info.readme_path.read_text(encoding="utf-8")
            lines.append("Description-Content-Type: text/markdown")

        lines.append("")
        if readme_content:
            lines.append(readme_content.rstrip())
            lines.append("")

        target.joinpath("METADATA").write_text("\n".join(lines), encoding="utf-8")

    def _write_wheel_file(self, target: Path) -> None:
        content = [
            "Wheel-Version: 1.0",
            "Generator: wm_build_backend 1.0",
            "Root-Is-Purelib: true",
            f"Tag: {DIST_TAG}",
            "",
        ]
        target.joinpath("WHEEL").write_text("\n".join(content), encoding="utf-8")

    def _write_entry_points(self, target: Path) -> None:
        entries = ["[console_scripts]"]
        for name, value in self.info.scripts.items():
            entries.append(f"{name} = {value}")
        entries.append("")
        target.joinpath("entry_points.txt").write_text("\n".join(entries), encoding="utf-8")

    def _build_records(self, build_root: Path, exclude: set[Path]) -> List[str]:
        records: List[str] = []
        for file_path in sorted(p for p in build_root.rglob("*") if p.is_file()):
            rel = file_path.relative_to(build_root)
            if rel in exclude:
                continue
            digest = hashlib.sha256(file_path.read_bytes()).digest()
            b64 = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
            size = file_path.stat().st_size
            records.append(f"{rel.as_posix()},sha256={b64},{size}")
        return records


def _builder() -> _Builder:
    return _Builder(Path(os.getcwd()))


def get_requires_for_build_wheel(config_settings: Optional[dict] = None) -> List[str]:
    return _builder().get_requires_for_build()


def get_requires_for_build_sdist(config_settings: Optional[dict] = None) -> List[str]:
    return _builder().get_requires_for_build()


def prepare_metadata_for_build_wheel(
    metadata_directory: str, config_settings: Optional[dict] = None
) -> str:
    return _builder().prepare_metadata(metadata_directory)


def build_wheel(
    wheel_directory: str,
    config_settings: Optional[dict] = None,
    metadata_directory: Optional[str] = None,
) -> str:
    return _builder().build_wheel(wheel_directory)


def build_sdist(sdist_directory: str, config_settings: Optional[dict] = None) -> str:
    return _builder().build_sdist(sdist_directory)


def build_editable(
    wheel_directory: str,
    config_settings: Optional[dict] = None,
    metadata_directory: Optional[str] = None,
) -> str:
    return _builder().build_editable(wheel_directory)
