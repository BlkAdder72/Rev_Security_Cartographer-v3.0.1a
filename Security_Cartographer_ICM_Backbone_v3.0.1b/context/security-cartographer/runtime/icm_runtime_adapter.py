"""Integration adapter for mandatory Security Cartographer ICM boundaries.

This module gives an existing orchestrator a small Python API while keeping the
security decisions in the deterministic security_cartographer CLI/module.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class IntegrationError(RuntimeError):
    """The ICM runtime boundary could not be established or enforced."""


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IntegrationError(f"Cannot read valid JSON from {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise IntegrationError(f"Expected a JSON object in {path}")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class VerifiedICMRun:
    """Paths and identity for one verified ICM runtime bundle."""

    run_id: str
    output_dir: Path
    envelope_path: Path
    bundle_root: Path
    instructions: Path
    context: Path
    memory: Path


class CartographerRuntime:
    """Connect Security Cartographer to an existing ICM orchestrator."""

    def __init__(
        self,
        *,
        policy: str | Path,
        manifest: str | Path,
        seal: str | Path,
        key_file: str | Path,
    ) -> None:
        self.policy = Path(policy).resolve()
        self.manifest = Path(manifest).resolve()
        self.seal = Path(seal).resolve()
        self.key_file = Path(key_file).resolve()
        for required in (self.policy, self.manifest, self.seal, self.key_file):
            if not required.is_file():
                raise IntegrationError(f"Required control-plane file is missing: {required}")

    @staticmethod
    def _invoke(arguments: list[str]) -> subprocess.CompletedProcess[str]:
        command = [sys.executable, "-m", "security_cartographer", *arguments]
        return subprocess.run(command, text=True, capture_output=True, check=False)

    def verify(
        self,
        workspace: str | Path,
        output_dir: str | Path,
        *,
        make_read_only: bool = True,
    ) -> VerifiedICMRun:
        """Verify sources and return the only ICM root the agent may consume."""

        workspace_path = Path(workspace).resolve()
        run_output = Path(output_dir).resolve()
        if not workspace_path.is_dir():
            raise IntegrationError(f"ICM workspace does not exist: {workspace_path}")
        if run_output.exists() and any(run_output.iterdir()):
            raise IntegrationError(
                f"Verified-run output must be new or empty; refusing to mix runs: {run_output}"
            )
        run_output.mkdir(parents=True, exist_ok=True)

        result = self._invoke([
            "verify",
            str(workspace_path),
            "--policy", str(self.policy),
            "--manifest", str(self.manifest),
            "--seal", str(self.seal),
            "--key-file", str(self.key_file),
            "--output", str(run_output),
        ])
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise IntegrationError(
                f"Cartographer verification failed closed with exit code "
                f"{result.returncode}: {detail}"
            )

        envelope_path = run_output / "context-envelope.json"
        envelope = _read_json(envelope_path)
        if envelope.get("status") != "verified":
            raise IntegrationError("Runtime envelope is not marked verified")
        backbone = envelope.get("icm_backbone")
        if not isinstance(backbone, dict) or backbone.get("mode") != "required":
            raise IntegrationError("Runtime envelope does not require the ICM backbone")
        layers = backbone.get("layers")
        if not isinstance(layers, dict) or set(layers) != {"instructions", "context", "memory"}:
            raise IntegrationError("Runtime envelope does not contain exactly three ICM layers")

        run_id = str(envelope.get("run_id", ""))
        if not run_id or "/" in run_id or "\\" in run_id or run_id in {".", ".."}:
            raise IntegrationError("Runtime envelope contains an invalid run_id")

        bundle_root = (run_output / "trusted-context" / run_id / "icm").resolve()
        if not _inside(bundle_root, run_output) or not bundle_root.is_dir():
            raise IntegrationError("Verified ICM bundle is missing or escapes the run output")

        verified = VerifiedICMRun(
            run_id=run_id,
            output_dir=run_output,
            envelope_path=envelope_path,
            bundle_root=bundle_root,
            instructions=bundle_root / "instructions",
            context=bundle_root / "context",
            memory=bundle_root / "memory",
        )
        self.validate_run(verified)
        if make_read_only:
            self._make_read_only(verified)
        return verified

    def validate_run(self, run: VerifiedICMRun) -> None:
        """Revalidate envelope identity, layer structure, and every delivered hash."""

        envelope = _read_json(run.envelope_path)
        if envelope.get("status") != "verified" or envelope.get("run_id") != run.run_id:
            raise IntegrationError("Verified-run envelope identity changed")
        backbone = envelope.get("icm_backbone", {})
        if backbone.get("mode") != "required":
            raise IntegrationError("Verified-run envelope no longer requires ICM")
        for layer_path in (run.instructions, run.context, run.memory):
            if not layer_path.is_dir() or not _inside(layer_path.resolve(), run.bundle_root):
                raise IntegrationError(f"Required ICM runtime layer is missing: {layer_path}")

        entries = envelope.get("entries")
        if not isinstance(entries, list):
            raise IntegrationError("Verified-run envelope has no entry inventory")
        for entry in entries:
            if not isinstance(entry, dict):
                raise IntegrationError("Verified-run envelope contains an invalid entry")
            relative_name = str(entry.get("file", ""))
            expected_hash = str(entry.get("sha256", ""))
            delivered = (run.output_dir / relative_name).resolve()
            if not _inside(delivered, run.bundle_root) or not delivered.is_file():
                raise IntegrationError(f"Delivered ICM file is missing or outside the bundle: {relative_name}")
            if _sha256(delivered) != expected_hash:
                raise IntegrationError(f"Delivered ICM file failed its hash check: {relative_name}")

    @staticmethod
    def _make_read_only(run: VerifiedICMRun) -> None:
        """Remove ordinary write bits; production should also use a protected mount."""

        for path in sorted(run.bundle_root.rglob("*"), reverse=True):
            try:
                mode = path.stat().st_mode
                path.chmod(mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
            except OSError as exc:
                raise IntegrationError(f"Could not make runtime bundle read-only: {path}: {exc}") from exc
        try:
            mode = run.bundle_root.stat().st_mode
            run.bundle_root.chmod(mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
        except OSError as exc:
            raise IntegrationError(f"Could not make runtime bundle read-only: {exc}") from exc

    def check_action(
        self,
        run: VerifiedICMRun,
        action: str | Path,
        decision: str | Path,
        *,
        audit: str | Path | None = None,
    ) -> dict[str, Any]:
        """Revalidate the bundle and obtain a deterministic action decision."""

        self.validate_run(run)
        action_path = Path(action).resolve()
        action_body = _read_json(action_path)
        if action_body.get("source_trust") == "verified-context":
            if action_body.get("context_run_id") != run.run_id:
                raise IntegrationError(
                    "A verified-context action must include the exact current context_run_id"
                )

        decision_path = Path(decision).resolve()
        decision_path.parent.mkdir(parents=True, exist_ok=True)
        arguments = [
            "check-action",
            "--action", str(action_path),
            "--policy", str(self.policy),
            "--manifest", str(self.manifest),
            "--seal", str(self.seal),
            "--key-file", str(self.key_file),
            "--context-envelope", str(run.envelope_path),
            "--decision", str(decision_path),
        ]
        if audit is not None:
            audit_path = Path(audit).resolve()
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            arguments.extend(["--audit", str(audit_path)])

        result = self._invoke(arguments)
        if result.returncode not in {0, 3}:
            detail = (result.stderr or result.stdout).strip()
            raise IntegrationError(
                f"Action boundary failed with exit code {result.returncode}: {detail}"
            )
        body = _read_json(decision_path)
        if bool(body.get("allowed")) != (result.returncode == 0):
            raise IntegrationError("Action decision file conflicts with the process exit code")
        return body

