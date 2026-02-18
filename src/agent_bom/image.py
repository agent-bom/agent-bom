"""Docker image scanning — extract packages from container images.

Two strategies, tried in order:

1. **Syft** (preferred): if ``syft`` is on PATH, run:
       syft <image> -o cyclonedx-json
   and parse the output with the existing CycloneDX parser.

2. **Docker CLI fallback**: if Syft is not available but ``docker`` is:
   - ``docker inspect`` to confirm the image exists / get metadata
   - Snapshot the container filesystem via ``docker create`` + ``docker export``
     then scan common package manager manifest files (pip, npm, etc.)
   - This is a best-effort approach; Syft will always produce richer results.

Usage from cli.py::

    from agent_bom.image import scan_image, ImageScanError
    packages, strategy = scan_image("myapp:latest")
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Optional

from agent_bom.models import Package
from agent_bom.sbom import parse_cyclonedx


class ImageScanError(Exception):
    """Raised when an image cannot be scanned."""


# ─── Syft strategy ────────────────────────────────────────────────────────────


def _syft_available() -> bool:
    return shutil.which("syft") is not None


def _scan_with_syft(image_ref: str) -> list[Package]:
    """Run Syft and parse its CycloneDX JSON output."""
    try:
        result = subprocess.run(
            ["syft", image_ref, "-o", "cyclonedx-json", "--quiet"],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        raise ImageScanError("syft not found")
    except subprocess.TimeoutExpired:
        raise ImageScanError(f"syft timed out scanning {image_ref}")

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise ImageScanError(f"syft exited {result.returncode}: {stderr[:200]}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise ImageScanError(f"syft produced invalid JSON: {e}")

    return parse_cyclonedx(data)


# ─── Docker CLI fallback ──────────────────────────────────────────────────────


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _docker_inspect(image_ref: str) -> dict:
    """Return docker inspect output for the image (pulls if needed)."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "--type", "image", image_ref],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except FileNotFoundError:
        raise ImageScanError("docker not found")

    if result.returncode != 0:
        # Try pulling first
        pull = subprocess.run(
            ["docker", "pull", image_ref],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if pull.returncode != 0:
            raise ImageScanError(
                f"Image not found locally and pull failed: {image_ref}"
            )
        result = subprocess.run(
            ["docker", "inspect", "--type", "image", image_ref],
            capture_output=True,
            text=True,
            timeout=60,
        )

    try:
        return json.loads(result.stdout)[0]
    except (json.JSONDecodeError, IndexError) as e:
        raise ImageScanError(f"docker inspect output parse error: {e}")


def _packages_from_tar(tar_path: Path) -> list[Package]:
    """Extract packages from a container filesystem tar archive.

    Scans for:
    - Python: site-packages RECORD/METADATA files
    - Node: node_modules/*/package.json (name + version)
    - OS packages: /var/lib/dpkg/status (Debian/Ubuntu)
    - OS packages: /var/lib/rpm/Packages (handled via sqlite3 in Python)
    """
    packages: list[Package] = []
    seen: set[tuple[str, str]] = set()

    def _add(name: str, version: str, ecosystem: str, purl: Optional[str] = None) -> None:
        key = (name, ecosystem)
        if key not in seen:
            seen.add(key)
            packages.append(Package(
                name=name,
                version=version,
                ecosystem=ecosystem,
                purl=purl or f"pkg:{ecosystem}/{name}@{version}",
                is_direct=False,
                resolved_from_registry=False,
            ))

    try:
        with tarfile.open(tar_path, "r") as tf:
            names = tf.getnames()

            # --- Python: dist-info METADATA ---
            for member_name in names:
                if member_name.endswith(".dist-info/METADATA"):
                    try:
                        member = tf.getmember(member_name)
                        f = tf.extractfile(member)
                        if f is None:
                            continue
                        pkg_name = pkg_version = ""
                        for raw_line in f:
                            line = raw_line.decode("utf-8", errors="ignore").strip()
                            if line.startswith("Name:"):
                                pkg_name = line.split(":", 1)[1].strip()
                            elif line.startswith("Version:"):
                                pkg_version = line.split(":", 1)[1].strip()
                            if pkg_name and pkg_version:
                                break
                        if pkg_name and pkg_version:
                            _add(pkg_name, pkg_version, "pypi")
                    except Exception:
                        continue

            # --- Node: node_modules/*/package.json ---
            for member_name in names:
                if (
                    "/node_modules/" in member_name
                    and member_name.endswith("package.json")
                    and member_name.count("/node_modules/") == 1
                ):
                    try:
                        member = tf.getmember(member_name)
                        f = tf.extractfile(member)
                        if f is None:
                            continue
                        data = json.loads(f.read().decode("utf-8", errors="ignore"))
                        pkg_name = data.get("name", "")
                        pkg_version = data.get("version", "unknown")
                        if pkg_name:
                            _add(pkg_name, pkg_version, "npm")
                    except Exception:
                        continue

            # --- Debian/Ubuntu: dpkg status ---
            dpkg_status = "var/lib/dpkg/status"
            if dpkg_status in names:
                try:
                    member = tf.getmember(dpkg_status)
                    f = tf.extractfile(member)
                    if f:
                        content = f.read().decode("utf-8", errors="ignore")
                        pkg_name = pkg_version = ""
                        for line in content.splitlines():
                            if line.startswith("Package:"):
                                pkg_name = line.split(":", 1)[1].strip()
                            elif line.startswith("Version:"):
                                pkg_version = line.split(":", 1)[1].strip()
                            elif line == "" and pkg_name and pkg_version:
                                _add(pkg_name, pkg_version, "deb",
                                     f"pkg:deb/debian/{pkg_name}@{pkg_version}")
                                pkg_name = pkg_version = ""
                except Exception:
                    pass
    except tarfile.TarError as e:
        raise ImageScanError(f"Failed to read container filesystem: {e}")

    return packages


def _scan_with_docker(image_ref: str) -> list[Package]:
    """Export container filesystem and scan package manager files."""
    # Confirm image exists / pull it
    _docker_inspect(image_ref)

    container_id: Optional[str] = None
    try:
        # Create a stopped container
        result = subprocess.run(
            ["docker", "create", image_ref],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise ImageScanError(f"docker create failed: {result.stderr.strip()[:200]}")
        container_id = result.stdout.strip()

        with tempfile.TemporaryDirectory() as tmpdir:
            tar_path = Path(tmpdir) / "fs.tar"

            export = subprocess.run(
                ["docker", "export", "-o", str(tar_path), container_id],
                capture_output=True,
                timeout=300,
            )
            if export.returncode != 0:
                raise ImageScanError("docker export failed")

            return _packages_from_tar(tar_path)

    finally:
        if container_id:
            subprocess.run(
                ["docker", "rm", container_id],
                capture_output=True,
                timeout=30,
            )


# ─── Public API ───────────────────────────────────────────────────────────────


def scan_image(image_ref: str) -> tuple[list[Package], str]:
    """Scan a Docker image and return (packages, strategy_used).

    Tries Syft first, then Docker CLI fallback.

    Args:
        image_ref: Docker image reference, e.g. ``myapp:latest``,
                   ``ghcr.io/org/image:sha256-abc``, ``nginx:1.25``

    Returns:
        A tuple ``(packages, strategy)`` where strategy is one of
        ``"syft"``, ``"docker"``.

    Raises:
        ImageScanError: If neither Syft nor Docker CLI is available,
                        or if the image cannot be found/pulled.
    """
    if _syft_available():
        packages = _scan_with_syft(image_ref)
        return packages, "syft"

    if _docker_available():
        packages = _scan_with_docker(image_ref)
        return packages, "docker"

    raise ImageScanError(
        "Neither 'syft' nor 'docker' found on PATH. "
        "Install Syft (https://github.com/anchore/syft) or Docker to enable image scanning."
    )


def image_to_purl(image_ref: str) -> str:
    """Convert a Docker image reference to a Package URL.

    Examples:
      nginx:1.25               → pkg:oci/nginx:1.25
      ghcr.io/org/app:v1.0.0  → pkg:oci/org/app:v1.0.0?repository_url=ghcr.io
    """
    if "://" in image_ref:
        # Strip protocol if someone passes a full URL
        image_ref = image_ref.split("://", 1)[1]

    parts = image_ref.split("/", 1)
    if len(parts) == 2 and ("." in parts[0] or ":" in parts[0]):
        # Has a registry hostname
        registry, rest = parts
        return f"pkg:oci/{rest}?repository_url={registry}"
    else:
        return f"pkg:oci/{image_ref}"
