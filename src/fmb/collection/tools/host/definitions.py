from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fmb.collection.tools.host.toolchain import tree_sha256
from fmb.collection.tools.kape.paths import KAPEFILES_DIR

DEFAULT_EXPORT_FORMAT = "csv"
DISABLED_FOLDER = "!disabled"


class KapeDefinitionError(ValueError):
    pass


@dataclass(frozen=True)
class TargetRule:
    requested_target: str
    definition: str
    definition_id: str
    name: str
    category: str
    path: str
    file_mask: str
    recursive: bool
    save_as: str | None
    always_add_to_queue: bool


@dataclass(frozen=True)
class ModuleProcessor:
    requested_module: str
    module_name: str
    definition: str
    definition_id: str
    category: str
    export_format: str
    file_mask: str | None
    executable: str
    command_line: str


def _load_yaml(text: str, *, label: str) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as error:
        raise KapeDefinitionError(
            "reading KAPE definitions requires PyYAML in the analysis environment"
        ) from error
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise KapeDefinitionError(f"{label} is not valid YAML: {error}") from error
    if not isinstance(loaded, dict):
        raise KapeDefinitionError(f"{label} is not a KAPE definition mapping")
    return loaded


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _flag(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return _text(value).casefold() in {"true", "yes", "1"}


def _is_disabled_member(member: str) -> bool:
    return any(part.casefold() == DISABLED_FOLDER for part in member.split("/"))


class KapeDefinitions:

    def __init__(
        self,
        root: Path = KAPEFILES_DIR,
        *,
        bundled_targets: dict[str, Path] | None = None,
    ) -> None:
        self.root = root.expanduser().resolve()
        if not self.root.is_dir():
            raise KapeDefinitionError(f"definitions folder does not exist: {self.root}")
        self.tree_sha256 = tree_sha256(self.root)[0]
        self._bundled_targets = {
            key.casefold(): Path(value) for key, value in (bundled_targets or {}).items()
        }
        self._targets: dict[str, str] = {}
        self._modules: dict[str, str] = {}
        self._texts: dict[str, str] = {}
        for path in sorted(self.root.rglob("*"), key=lambda item: item.relative_to(self.root).parts):
            member = path.relative_to(self.root).as_posix()
            if path.is_symlink() or not path.is_file() or _is_disabled_member(member):
                continue
            lowered = "/" + member.casefold()
            stem = path.name
            if lowered.endswith(".tkape") and "/targets/" in lowered:
                self._register(self._targets, stem[: -len(".tkape")], member)
            elif lowered.endswith(".mkape") and "/modules/" in lowered:
                self._register(self._modules, stem[: -len(".mkape")], member)
        for member in list(self._targets.values()) + list(self._modules.values()):
            self._texts[member] = (self.root / member).read_text(encoding="utf-8-sig")

    @staticmethod
    def _register(table: dict[str, str], name: str, member: str) -> None:
        key = name.casefold()
        existing = table.get(key)
        if existing is not None and existing != member:
            if member.count("/") >= existing.count("/"):
                return
        table[key] = member

    def _target_source(self, name: str) -> tuple[str, str]:
        key = name.casefold()
        bundled = self._bundled_targets.get(key)
        if bundled is not None:
            if not bundled.is_file():
                raise KapeDefinitionError(f"bundled target definition is missing: {bundled}")
            return f"bundled:{bundled.name}", bundled.read_text(encoding="utf-8-sig")
        member = self._targets.get(key)
        if member is None:
            raise KapeDefinitionError(f"target definition not found: {name}")
        return member, self._texts[member]

    def target_rules(self, names: list[str]) -> list[TargetRule]:
        rules: list[TargetRule] = []
        processed_ids: set[str] = set()

        def expand(requested: str, name: str) -> None:
            source, text = self._target_source(name)
            definition = _load_yaml(text, label=source)
            definition_id = _text(definition.get("Id")) or source
            if definition_id in processed_ids:
                return
            processed_ids.add(definition_id)
            for item in definition.get("Targets") or []:
                if not isinstance(item, dict):
                    raise KapeDefinitionError(f"{source} has a malformed target entry")
                path = _text(item.get("Path"))
                if path.casefold().endswith(".tkape"):
                    expand(requested, Path(path).name[: -len(".tkape")])
                    continue
                if not path:
                    raise KapeDefinitionError(f"{source} has a target without a Path")
                unsupported = [key for key in ("MinSize", "MaxSize") if item.get(key) not in (None, "")]
                if _text(item.get("FileMask")).casefold().startswith("regex:"):
                    unsupported.append("regex FileMask")
                if unsupported:
                    raise KapeDefinitionError(
                        f"{source} uses target options this collector does not implement: {', '.join(unsupported)}"
                    )
                rules.append(
                    TargetRule(
                        requested_target=requested,
                        definition=source,
                        definition_id=definition_id,
                        name=_text(item.get("Name")) or name,
                        category=_text(item.get("Category")),
                        path=path,
                        file_mask=_text(item.get("FileMask")) or "*",
                        recursive=_flag(item.get("Recursive")),
                        save_as=_text(item.get("SaveAsFileName")) or None,
                        always_add_to_queue=_flag(item.get("AlwaysAddToQueue")),
                    )
                )

        for name in names:
            expand(name, name)
        return rules

    def _module_source(self, name: str) -> tuple[str, str]:
        member = self._modules.get(name.casefold())
        if member is None:
            raise KapeDefinitionError(f"module definition not found: {name}")
        return member, self._texts[member]

    def module_processors(self, names: list[str]) -> list[ModuleProcessor]:
        processors: list[ModuleProcessor] = []
        processed_ids: set[str] = set()

        def expand(requested: str, name: str) -> None:
            source, text = self._module_source(name)
            definition = _load_yaml(text, label=source)
            definition_id = _text(definition.get("Id")) or source
            if definition_id in processed_ids:
                return
            processed_ids.add(definition_id)
            module_format = _text(definition.get("ExportFormat")) or DEFAULT_EXPORT_FORMAT
            entries = definition.get("Processors") or []
            compound = [
                item
                for item in entries
                if isinstance(item, dict)
                and _text(item.get("Executable")).casefold().endswith(".mkape")
            ]
            if compound:
                for item in compound:
                    expand(requested, Path(_text(item.get("Executable"))).name[: -len(".mkape")])
                return
            chosen: dict[str, Any] | None = None
            for item in entries:
                if not isinstance(item, dict):
                    continue
                if (_text(item.get("ExportFormat")) or module_format).casefold() == DEFAULT_EXPORT_FORMAT.casefold():
                    chosen = item
                    break
            if chosen is None and entries and isinstance(entries[0], dict):
                chosen = entries[0]
            if chosen is None:
                raise KapeDefinitionError(f"{source} declares no processor")
            processors.append(
                ModuleProcessor(
                    requested_module=requested,
                    module_name=name,
                    definition=source,
                    definition_id=definition_id,
                    category=_text(definition.get("Category")) or "Uncategorized",
                    export_format=_text(chosen.get("ExportFormat")) or module_format,
                    file_mask=_text(definition.get("FileMask")) or None,
                    executable=_text(chosen.get("Executable")),
                    command_line=_text(chosen.get("CommandLine")),
                )
            )

        for name in names:
            expand(name, name)
        return processors


def split_file_masks(mask: str) -> list[str]:
    parts = [part.strip() for part in mask.split("|")]
    return [part.replace("%3A", ":").replace("%3a", ":") for part in parts if part]


__all__ = [
    "KapeDefinitionError",
    "KapeDefinitions",
    "ModuleProcessor",
    "TargetRule",
    "split_file_masks",
]
