"""Files of a service sent from the web interface, kept on the authority.

The configuration names files by path on the authority (``service-file`` and
``files`` of ``config service``); a browser has no path to give, so what it
sends is written under the state directory and that path goes in the form:

    <state>/service-uploads/<service>/<file name>

The mutation the authority signs then carries the content to every node that
hosts the service. Reading back is limited to the paths a service names, so
the web interface does not become a way to read any file of the authority.
"""

from __future__ import annotations

import base64
import binascii
from pathlib import Path

import yaml

from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.store import state_directory
from usmd_rdsh.node.services import (
    MAX_FILES_BYTES,
    ServiceFileError,
    check_file_name,
    load_yaml_stream,
)


class UploadError(ValueError):
    """A file the interface refuses, with the reason."""


def _service_name(value: object) -> str:
    name = str(value or "")
    try:
        return check_file_name(name)
    except ServiceFileError as exc:
        raise UploadError("the service name cannot name a directory") from exc


def save(request: dict) -> dict:
    """``{service, name, content (base64), service_file?}`` -> where it was written.

    With ``service_file`` the file must be a YAML stream holding a document
    named after the service, which is what the signing refuses otherwise.
    """
    service = _service_name(request.get("service"))
    try:
        name = check_file_name(str(request.get("name", "")))
        content = base64.b64decode(str(request.get("content", "")), validate=True)
    except ServiceFileError as exc:
        raise UploadError(str(exc)) from exc
    except (binascii.Error, ValueError) as exc:
        raise UploadError("content is base64") from exc
    if len(content) > MAX_FILES_BYTES:
        raise UploadError(f"a file is at most {MAX_FILES_BYTES // 1024} KiB")
    found: list[str] = []
    if request.get("service_file"):
        try:
            documents = load_yaml_stream(content.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, yaml.YAMLError) as exc:
            raise UploadError(f"not a UTF-8 YAML file: {exc}") from exc
        found = [str(d.get("name")) for d in documents if isinstance(d, dict)]
        if service not in found:
            raise UploadError(f"no document with 'name: {service}' in this file "
                              f"(found: {', '.join(found) or 'none'})")
    path = state_directory().path("service-uploads", service, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return {"path": str(path), "name": name, "size": len(content), "services": found}


def read(service: str, path: str) -> dict:
    """The content of a file the service names (its service file or one of its files)."""
    rows = RUNTIME.config("service") or {}
    row = rows.get(service)
    if row is None:
        raise UploadError(f"no service '{service}'")
    named = {p for p in [row.service_file, *row.files] if p}
    if path not in named:
        raise UploadError("only the files a service names can be read")
    try:
        content = Path(path).expanduser().read_bytes()
    except OSError as exc:
        raise UploadError(f"cannot read {path}: {exc.strerror}") from exc
    try:
        return {"path": path, "text": content.decode("utf-8"), "size": len(content)}
    except UnicodeDecodeError:
        return {"path": path, "text": None, "size": len(content)}
