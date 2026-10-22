"""What the management plane keeps on disk, under ``~/.usmd``.

    config.json      the committed configuration document (view tree)
    api-tokens.json  the web/API tokens: key id, name, profile, SHA-256 digest

Both are written atomically through ``nan_runtime.state.StateDirectory``, so a
node killed in the middle of a commit restarts with the previous configuration
rather than with half a file.
"""

from __future__ import annotations

import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from nan_actions import ActionActor
from nan_actions.api.token import ApiToken
from nan_actions.views import ConfigDocument
from nan_runtime.state import StateDirectory

from usmd_rdsh.cli.permissions import TOKEN_PROFILES

#: The state root, overridable for tests and for several nodes on one host.
STATE_ENV_VAR = "USMD_STATE_DIR"

_CONFIG_FILE = "config.json"
_TOKENS_FILE = "api-tokens.json"


def state_directory() -> StateDirectory:
    """``$USMD_STATE_DIR`` or ``~/.usmd``, where node.properties already lives."""
    root = os.getenv(STATE_ENV_VAR) or os.path.expanduser("~/.usmd")
    return StateDirectory(Path(root))


class ConfigStore:
    """Loads and saves the configuration document.

    By default ``config.json`` in the state directory; with a ``usmd.yaml``
    (``usmd --config``), that file, in the layout of ``usmd.example.yaml``.
    """

    def __init__(self, state: StateDirectory | None = None, yaml_path: Path | None = None) -> None:
        self._state = state or state_directory()
        self.yaml_path = yaml_path
        self.bootstrap = False
        self.keys_file = ""
        self.warnings: list[str] = []

    @property
    def path(self) -> Path:
        """Where the document is saved."""
        return self.yaml_path or self._state.path(_CONFIG_FILE)

    def load(self) -> ConfigDocument:
        """The saved document, or an empty one on a first start."""
        if self.yaml_path is not None:
            from usmd_rdsh.cli import yaml_config  # pylint: disable=import-outside-toplevel

            if not self.yaml_path.exists():
                return ConfigDocument()
            loaded = yaml_config.parse(self.yaml_path.read_text(encoding="utf-8"))
            self.bootstrap, self.keys_file = loaded.bootstrap, loaded.keys_file
            self.warnings = loaded.warnings
            return loaded.document
        return ConfigDocument.from_json(self._state.read_text(_CONFIG_FILE))

    def text(self, document: ConfigDocument) -> str:
        """What :meth:`save_now` writes."""
        if self.yaml_path is not None:
            from usmd_rdsh.cli import yaml_config  # pylint: disable=import-outside-toplevel

            return yaml_config.dump(document, bootstrap=self.bootstrap, keys_file=self.keys_file)
        return document.to_json() + "\n"

    async def save(self, document: ConfigDocument) -> None:
        """Write *document*; the ``on_commit`` hook of every view session."""
        self.save_now(document)

    def save_now(self, document: ConfigDocument) -> None:
        """Synchronous form, for a caller outside the event loop's coroutines."""
        if self.yaml_path is not None:
            tmp = self.yaml_path.with_suffix(self.yaml_path.suffix + ".tmp")
            tmp.write_text(self.text(document), encoding="utf-8")
            tmp.replace(self.yaml_path)
            return
        self._state.write_text(self.text(document), _CONFIG_FILE)


@dataclass(slots=True)
class StoredToken:
    """A token as kept on disk. The secret itself is never stored."""

    key_id: str
    name: str
    profile: str
    digest: str
    created: float


class TokenStore:
    """The tokens the web interface and the API accept."""

    def __init__(self, state: StateDirectory | None = None) -> None:
        self._state = state or state_directory()
        self.last_used: dict[str, float] = {}
        # Web logins (username/password): in memory only, they die with the node.
        self.sessions: dict[str, tuple[str, str, float]] = {}  # key id -> (digest, name, until)

    def mint_session(self, name: str, ttl_s: float = 12 * 3600) -> ApiToken:
        """A token for one web login, never written to disk."""
        token = ApiToken.mint()
        now = time.time()
        self.sessions = {k: v for k, v in self.sessions.items() if v[2] > now}
        self.sessions[token.key_id] = (token.digest, name, now + ttl_s)
        return token

    def all(self) -> list[StoredToken]:
        """Every token, oldest first."""
        raw = self._state.read_json(_TOKENS_FILE, default=[]) or []
        return [StoredToken(**entry) for entry in raw]

    def _write(self, tokens: list[StoredToken]) -> None:
        self._state.write_json([asdict(t) for t in tokens], _TOKENS_FILE, mode=0o600)

    def mint(self, name: str, profile: str) -> ApiToken:
        """Create a token; its plaintext is returned once and never stored."""
        if profile not in TOKEN_PROFILES:
            raise ValueError(f"unknown profile '{profile}'")
        token = ApiToken.mint()
        tokens = self.all()
        tokens.append(
            StoredToken(
                key_id=token.key_id,
                name=name,
                profile=profile,
                digest=token.digest,
                created=time.time(),
            )
        )
        self._write(tokens)
        return token

    def revoke(self, key_id: str) -> bool:
        """Remove a token. False when there was none with this key id."""
        tokens = self.all()
        kept = [t for t in tokens if t.key_id != key_id]
        if len(kept) == len(tokens):
            return False
        self._write(kept)
        return True

    def actor_for(self, token: ApiToken) -> ActionActor | None:
        """The actor a presented token acts as, or None."""
        session = self.sessions.get(token.key_id)
        if session is not None and session[2] > time.time() and token.matches(session[0]):
            self.last_used[token.key_id] = time.time()
            return ActionActor.authenticated(user_id=token.key_id, username=session[1],
                                             permissions=TOKEN_PROFILES["admin"], source="api")
        for stored in self.all():
            if stored.key_id == token.key_id and token.matches(stored.digest):
                # Kept in memory: the dashboard polls every few seconds, and a
                # disk write per request would be the busiest thing on the node.
                self.last_used[stored.key_id] = time.time()
                return ActionActor.authenticated(
                    user_id=stored.key_id,
                    username=stored.name,
                    permissions=TOKEN_PROFILES.get(stored.profile, ()),
                    source="api",
                )
        return None
