"""An elected operator managing the other nodes, one by one or together [ARCH 12.5].

Two sides of Operate (NCP 0x0016):

* **served** - every node answers with a console of its own per (operator,
  session), holding ``usmd:read`` and ``usmd:write`` but never ``api:manage``:
  authority keys, creation tokens and API tokens stay local. Each line is
  logged with the operator it comes from.
* **operator** - in the console (local, ``usmd``, web) of an elected
  usc-operator or usd-operator::

      node <id|address>          the console of one node; 'exit' leaves it
      on <targets> <line>        one line on every target, outputs by node
      on <targets>               every following line goes to every target
      disconnect                 back to this node's console at once

  targets, combined (each must match):
      all | node <id|address> | usd <USDN> | mutation <name>
      | area <name> | state <state> | role <role>

A usd-operator reaches the nodes of its USD; a usc-operator also those of
every other USD of the USC, through the usc-operator elected there
(``config trust usc-peer`` names one contact node per USD). A confirmation
asked by the targets is asked once, here, for all of them.

The exchange is the local console socket's (see ``control``), one JSON object
each way, plus ``nodes`` (the node table), ``schema`` and ``form`` (the web
configuration forms) and ``close``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from nan_actions import ActionActor
from nan_actions.ports import get_confirm_prompt
from nan_actions.views.errors import ViewError
from nan_runtime.log import LogLevel, emit, log

from usmd_rdsh.cli.control import run_line
from usmd_rdsh.cli.permissions import READ, WRITE
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.node.ncp.codec import Role
from usmd_rdsh.node.ncp.transport import NcpRemoteError, NcpTimeout
from usmd_rdsh.node.states import State

if TYPE_CHECKING:  # pragma: no cover
    from usmd_rdsh.cli.shell import ShellFactory, UsmdShell

audit = logging.getLogger("usmd_rdsh.operate")

#: What a remote operator holds on a node: everything but ``api:manage``.
OPERATOR_PERMISSIONS = (READ, WRITE)
SOURCE = "ncp"
SESSION_IDLE_S = 900.0
MAX_SESSIONS = 64
PARALLEL = 16
FOREIGN_CACHE_S = 30.0
LISTING_ATTEMPTS = 2  # a USD that does not answer the listing is skipped after 6 s
_NOT_CONFIRMED = "Not confirmed: nothing was done."
SELECTORS = {"all": 0, "node": 1, "usd": 1, "mutation": 1, "area": 1, "state": 1, "role": 1}
USAGE = ("on <targets> [<line>]: targets are all, node <id|address>, usd <USDN>, "
         "mutation <name>, area <name>, state <state>, role <role>")


def _name(value: str) -> str:
    return value.lower().replace("_", "-")


def node_rows(node) -> list[dict[str, Any]]:
    """This node's USD as an operator sees it: one row per admitted node."""
    usd = node.signed.usd
    usdn = usd.usdn if usd else ""
    area_names = {a.area_id: a.name for a in usd.areas} if usd else {}
    rows: list[dict[str, Any]] = []
    seen = set()
    for entry in node.tables.nodes.sorted():
        if node.tables.exclusions.is_excluded(entry.key):
            continue
        record = entry.record
        own = entry.key == node.key
        seen.add(record.node_id)
        rows.append(_row(node, record.node_id, node.settings.address if own else record.address,
                         node.state if own else node.peer_state(entry.key),
                         node.mutation if own else record.mutation, usdn, area_names))
    if node.node_id not in seen:
        rows.insert(0, _row(node, node.node_id, node.settings.address, node.state,
                            node.mutation, usdn, area_names))
    return rows


def _row(node, node_id, address, state, mutation, usdn, area_names) -> dict[str, Any]:
    areas = node.signed.areas_of_mutation(mutation) if mutation else set()
    return {"id": node_id, "address": address, "state": _name(State(state).name),
            "mutation": mutation, "areas": sorted(area_names.get(a, str(a)) for a in areas),
            "roles": sorted(_name(Role(r).name) for r, ids in node.operators.items()
                            if node_id in ids),
            "usdn": usdn}


# ---------------------------------------------------------------------------
# Served: the console a node lends an operator
# ---------------------------------------------------------------------------


class OperateServer:
    """One console shell per (operator key, session), closed after 15 idle minutes."""

    def __init__(self, factory: "ShellFactory") -> None:
        self._factory = factory
        self._sessions: dict[tuple[bytes, int], tuple["UsmdShell", float]] = {}

    @staticmethod
    def actor(origin: str) -> ActionActor:
        return ActionActor.authenticated(user_id=f"operator:{origin}",
                                         username=f"operator {origin}",
                                         permissions=OPERATOR_PERMISSIONS, source=SOURCE)

    def _shell(self, origin: str, sender: bytes, session: int) -> "UsmdShell":
        now = time.monotonic()
        self._sessions = {k: v for k, v in self._sessions.items()
                          if now - v[1] < SESSION_IDLE_S}
        key = (sender, session)
        if key in self._sessions:
            shell = self._sessions[key][0]
        else:
            while len(self._sessions) >= MAX_SESSIONS:
                del self._sessions[min(self._sessions, key=lambda k: self._sessions[k][1])]
            shell = self._factory.operator_shell(self.actor(origin))
        self._sessions[key] = (shell, now)
        return shell

    @property
    def sessions(self) -> int:
        return len(self._sessions)

    async def handle(self, origin: str, sender: bytes, session: int, payload: bytes) -> bytes:
        """The node's ``operate_handler``: JSON in, JSON out."""
        try:
            request = json.loads(payload)
            if not isinstance(request, dict):
                raise ValueError
        except ValueError:
            return _dump({"error": "one JSON object"})
        via = request.get("via")
        who = f"{via} via {origin}" if via else origin
        try:
            answer = await self._answer(who, sender, session, request)
        except ViewError as exc:
            answer = {"error": exc.message}
        return _dump(answer)

    async def _answer(self, who: str, sender: bytes, session: int,
                      request: dict[str, Any]) -> dict[str, Any]:
        if request.get("nodes"):
            return {"nodes": node_rows(RUNTIME.node)}
        if request.get("close"):
            self._sessions.pop((sender, session), None)
            return {"closed": True}
        if request.get("schema") or "form" in request:
            from usmd_rdsh.web import config_forms  # pylint: disable=import-outside-toplevel

            actor = self.actor(who)
            if request.get("schema"):
                return {**config_forms.schema(actor), "can_write": True}
            form = request["form"] if isinstance(request["form"], dict) else {}
            audit.warning("[OPERATE] Operator form from %s: '%s'%s", who, form.get("path"),
                          f" [{form.get('key')}]" if form.get("key") else "")
            return await config_forms.apply(actor, form)
        shell = self._shell(who, sender, session)
        if "complete" in request:
            return {"candidates": await shell.completions_async(str(request["complete"]))}
        line = str(request.get("line", ""))
        if "\n" in line or len(line) > 4096:
            return {"error": "one line, at most 4096 characters"}
        if line.strip():
            audit.warning("[OPERATE] Operator line from %s: '%s'", who, line)
        return await run_line(shell, line, request.get("confirm") is True)


def _dump(answer: dict[str, Any]) -> bytes:
    return json.dumps(answer).encode("utf-8")


SERVER: OperateServer | None = None


def install(factory: "ShellFactory") -> OperateServer:
    """Make the running node answer Operate with consoles of *factory*."""
    global SERVER  # pylint: disable=global-statement
    SERVER = OperateServer(factory)
    if RUNTIME.node is not None:
        RUNTIME.node.operate_handler = SERVER.handle
    return SERVER


# ---------------------------------------------------------------------------
# Operator: the nodes in reach, and talking to them
# ---------------------------------------------------------------------------


@dataclass
class Target:  # pylint: disable=too-many-instance-attributes
    """A node an operator may manage."""

    node_id: str
    address: str = ""
    state: str = ""
    mutation: str = ""
    areas: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    usdn: str = ""
    foreign: bool = False  # in another USD of the USC, reached through its operator

    @classmethod
    def of(cls, row: dict[str, Any], foreign: bool = False) -> "Target":
        return cls(str(row.get("id", "")), str(row.get("address", "")),
                   str(row.get("state", "")), str(row.get("mutation", "")),
                   list(row.get("areas") or []), list(row.get("roles") or []),
                   str(row.get("usdn", "")), foreign)

    def row(self) -> dict[str, Any]:
        return {"id": self.node_id, "address": self.address, "state": self.state,
                "mutation": self.mutation, "areas": self.areas, "roles": self.roles,
                "usdn": self.usdn, "foreign": self.foreign}


class OperateError(Exception):
    """A request an operator cannot make; the message says why."""


class Fleet:
    """The nodes this node's elected roles reach [ARCH 12.5]."""

    def __init__(self) -> None:
        self._foreign: dict[str, tuple[float, list[Target]]] = {}

    @staticmethod
    def _node():
        if RUNTIME.node is None:
            raise OperateError("the node is not running")
        return RUNTIME.node

    def scope(self) -> str:
        return self._node().operator_scope()

    def require_scope(self) -> str:
        scope = self.scope()
        if not scope:
            raise OperateError("this node is not an elected usc-operator or usd-operator: "
                               "it manages only itself [ARCH 12.4, 12.5]")
        return scope

    def own(self) -> list[Target]:
        return [Target.of(row) for row in node_rows(self._node())]

    def known(self) -> list[Target]:
        """This USD, and the other USDs as last listed: what Tab offers without waiting."""
        return self.own() + [t for _, targets in self._foreign.values() for t in targets]

    def other_usds(self) -> list[str]:
        """The other USDs of the USC in force."""
        node = self._node()
        own = node.signed.usd.usdn if node.signed.usd else ""
        return [u for u in (node.signed.usc.usd if node.signed.usc else []) if u != own]

    async def foreign(self, usdn: str) -> list[Target]:
        """The nodes of another USD, listed by its usc-operator (kept 30 s)."""
        cached = self._foreign.get(usdn)
        if cached is not None and time.monotonic() - cached[0] < FOREIGN_CACHE_S:
            return cached[1]
        node = self._node()
        raw = await node.operate_foreign(usdn, 0, _dump({"nodes": True}),
                                         attempts=LISTING_ATTEMPTS)
        answer = json.loads(raw)
        if "error" in answer:
            raise OperateError(f"USD {usdn}: {answer['error']}")
        targets = [Target.of(row, foreign=True) for row in answer.get("nodes", [])]
        self._foreign[usdn] = (time.monotonic(), targets)
        return targets

    async def everyone(self, *, quiet: bool = False) -> list[Target]:
        """Every node in reach; a USD that does not answer is reported and skipped."""
        targets = self.own()
        if self.require_scope() != "usc":
            return targets
        usds = self.other_usds()
        listings = await asyncio.gather(*(self.foreign(u) for u in usds), return_exceptions=True)
        for usdn, listing in zip(usds, listings):
            if isinstance(listing, BaseException):
                if not quiet:
                    log(f"% USD {usdn} not reached: {_reason(listing)}", LogLevel.WARNING)
                continue
            targets.extend(listing)
        return targets

    async def resolve(self, selectors: list[tuple[str, str]]) -> list[Target]:
        """The targets every selector matches."""
        scope = self.require_scope()
        usd_wanted = [v.upper() for k, v in selectors if k == "usd"]
        node_wanted = [v for k, v in selectors if k == "node"]
        own_usdn = self._node().signed.usd.usdn if self._node().signed.usd else ""
        if usd_wanted:
            if scope != "usc" and any(u != own_usdn for u in usd_wanted):
                raise OperateError("a usd-operator manages the nodes of its own USD only")
            pool = []
            for usdn in sorted(set(usd_wanted)):
                pool.extend(self.own() if usdn == own_usdn else await self.foreign(usdn))
        elif node_wanted:
            # Looked for in this USD first: no other USD is asked for a local node.
            pool = self.own()
            if scope == "usc" and not any(_matches_node(t, node_wanted[0]) for t in pool):
                pool = await self.everyone()
        else:
            pool = await self.everyone()
        chosen = [t for t in pool if all(_matches(t, k, v) for k, v in selectors)]
        for wanted in node_wanted:
            exact = [t for t in chosen if t.node_id == wanted.upper() or t.address == wanted]
            if exact:
                chosen = [t for t in chosen if t in exact]
            elif len(chosen) > 1:
                raise OperateError(f"'{wanted}' designates {len(chosen)} nodes: "
                                   + ", ".join(t.node_id for t in chosen))
        return chosen

    async def send(self, target: Target, session: int, request: dict[str, Any]) -> dict[str, Any]:
        """One exchange; an unreachable node is an ``error`` answer, never an exception."""
        node = self._node()
        payload = _dump(request)
        try:
            if target.node_id == node.node_id:
                if SERVER is None:
                    return {"error": "no console on this node"}
                raw = await SERVER.handle(node.node_id, node.key, session, payload)
            elif target.foreign:
                raw = await node.operate_foreign(target.usdn, session, payload, target.node_id)
            else:
                raw = await node.operate(target.node_id, session, payload)
            answer = json.loads(raw)
        except (NcpTimeout, NcpRemoteError, ValueError, OSError) as exc:
            return {"error": _reason(exc)}
        return answer if isinstance(answer, dict) else {"error": "not a JSON object"}


def _reason(exc: BaseException) -> str:
    if isinstance(exc, NcpTimeout):
        return "no answer"
    if isinstance(exc, NcpRemoteError):
        if exc.code == 0x0003 and exc.text == "unknown command":
            # A node of an earlier version: it predates Operate (0x0016).
            return ("this node does not know Operate (NCP 0x0016): install this version "
                    "of USMD-RDSH on it")
        return exc.text or f"error 0x{exc.code:04X}"
    return str(exc) or type(exc).__name__


def _matches_node(target: Target, wanted: str) -> bool:
    wanted_id = wanted.upper()
    return target.node_id == wanted_id or target.address == wanted or \
        (len(wanted) >= 4 and target.node_id.startswith(wanted_id))


def _matches(target: Target, kind: str, value: str) -> bool:
    if kind == "all":
        return True
    if kind == "node":
        return _matches_node(target, value)
    if kind == "usd":
        return target.usdn == value.upper()
    if kind == "mutation":
        return target.mutation == value
    if kind == "area":
        return value in target.areas
    if kind == "state":
        return target.state.startswith(_name(value))
    if kind == "role":
        return _name(value) in target.roles or _name(value) == "node-executor"
    return False


FLEET = Fleet()


#: What ``?`` says of each word, at the root and after ``on``.
ENTRIES = {"node": "Console of one node of the USD / USC (elected operators) [ARCH 12.5]",
           "on": "Run lines on several nodes: on <targets> [<line>] [ARCH 12.5]"}
DISCONNECT_HELP = "Back to the console of this node (leaves the remote node(s)) [ARCH 12.5]"
SELECTOR_HELP = {"all": "Every node in reach", "node": "One node: identifier or address",
                 "usd": "The nodes of a USD", "mutation": "The nodes hosting a mutation",
                 "area": "The nodes serving a service area", "state": "The nodes in a state",
                 "role": "The nodes elected to a role"}


def offered(actor: ActionActor) -> bool:
    """Whether ``node`` and ``on`` are offered at this prompt: an elected operator's own."""
    if actor.source == SOURCE:
        return False
    try:
        return bool(FLEET.scope())
    except OperateError:
        return False


def _values(kind: str) -> list[tuple[str, str]]:
    """(value, description) a selector may take, from what this node knows now."""
    node = RUNTIME.node
    if kind == "node":
        out = []
        for target in FLEET.known():
            where = f" (USD {target.usdn})" if target.foreign else ""
            out.append((target.node_id, f"{target.address} {target.state}"
                        f"{' ' + target.mutation if target.mutation else ''}{where}"))
            if target.address:
                out.append((target.address, target.node_id + where))
        return out
    if kind == "usd":
        own = node.signed.usd.usdn if node.signed.usd else ""
        usds = [(own, "this node's USD")] if own else []
        return usds + [(u, "another USD of the USC") for u in FLEET.other_usds()
                       if FLEET.scope() == "usc"]
    if kind == "mutation":
        return [(name, "mutation") for name in sorted(node.signed.mutations)]
    if kind == "area":
        usd = node.signed.usd
        return [(a.name, f"area {a.area_id}") for a in usd.areas] if usd else []
    if kind == "state":
        return [(_name(s.name), "") for s in State]
    if kind == "role":
        return [(_name(r.name), "") for r in Role]
    return []


def _choices(typed: str, pairs: list[tuple[str, str]]):
    from prompt_toolkit.completion import Completion  # pylint: disable=import-outside-toplevel

    seen = set()
    for value, description in pairs:
        if value.lower().startswith(typed.lower()) and value not in seen:
            seen.add(value)
            yield Completion(value, start_position=-len(typed), display=value,
                             display_meta=description)


def root_completions(typed: str):
    """``node`` and ``on`` among the first words."""
    return _choices(typed, list(ENTRIES.items()))


def completions(text: str, inner) -> list | None:
    """Tab after ``node`` / ``on``; None for any other line.

    *inner(text)* completes an ordinary console line: the line ``on`` runs.
    """
    stripped = text.lstrip()
    verb, space, rest = stripped.partition(" ")
    if not space or verb not in ENTRIES:
        return None
    words = list(re.finditer(r"\S+", rest))
    typing = words[-1].group() if words and not rest.endswith(" ") else ""
    settled = words[:-1] if typing else words
    if verb == "node":
        return [] if settled else list(_choices(typing, _values("node")))
    index, expect = 0, None
    while index < len(settled) and settled[index].group() in SELECTORS:
        kind = settled[index].group()
        if SELECTORS[kind] and index + 1 == len(settled):
            expect = kind
            break
        index += 1 + SELECTORS[kind]
    if expect:
        return list(_choices(typing, _values(expect)))
    if index < len(settled):  # the line itself: the console's own completion
        start = len(text) - len(rest) + settled[index].start()
        return list(inner(text[start:]))
    found = list(_choices(typing, list(SELECTOR_HELP.items())))
    if index:  # a target given: the line may start here
        found += list(inner(typing))
    return found


def is_complete(line: str, command_complete) -> bool:
    """Whether a ``node`` / ``on`` line could run as it stands (``<cr>`` of ``?``)."""
    verb, _, rest = line.strip().partition(" ")
    if verb == "node":
        return len(rest.split()) == 1
    try:
        selectors, command = parse_targets(rest)
    except OperateError:
        return False
    return bool(selectors) and (not command or command_complete(command))


def parse_targets(text: str) -> tuple[list[tuple[str, str]], str]:
    """``all usd X show node`` -> ([("all", ""), ("usd", "X")], "show node")."""
    words = list(re.finditer(r"\S+", text))
    selectors: list[tuple[str, str]] = []
    index = 0
    while index < len(words) and words[index].group() in SELECTORS:
        kind = words[index].group()
        if SELECTORS[kind]:
            if index + 1 >= len(words):
                raise OperateError(f"'{kind}' needs a value. {USAGE}")
            selectors.append((kind, words[index + 1].group()))
            index += 2
        else:
            selectors.append((kind, ""))
            index += 1
    rest = text[words[index].start():] if index < len(words) else ""
    return selectors, rest.strip()


# ---------------------------------------------------------------------------
# Operator: a console session on one node or several
# ---------------------------------------------------------------------------


class Remote:
    """Lines typed at an operator's console, sent to one target or several."""

    def __init__(self, targets: list[Target], fleet: Fleet = FLEET) -> None:
        self.targets = targets
        self.fleet = fleet
        self.session = secrets.randbits(64) or 1
        self.prompts: dict[str, str] = {}

    @property
    def single(self) -> bool:
        return len(self.targets) == 1

    def prompt(self, local: str) -> str:
        if self.single:
            target = self.targets[0]
            return f"{local}>{self.prompts.get(target.node_id) or target.node_id + '#'}"
        tail = "#"
        for text in self.prompts.values():
            if "(" in text:
                tail = text[text.index("("):]
                break
        return f"{local}>[{len(self.targets)} nodes]{tail}"

    async def _all(self, request: dict[str, Any],
                   targets: list[Target] | None = None) -> dict[str, dict[str, Any]]:
        targets = self.targets if targets is None else targets
        gate = asyncio.Semaphore(PARALLEL)

        async def one(target: Target) -> dict[str, Any]:
            async with gate:
                return await self.fleet.send(target, self.session, request)

        answers = await asyncio.gather(*(one(t) for t in targets))
        for target, answer in zip(targets, answers):
            if answer.get("prompt"):
                self.prompts[target.node_id] = answer["prompt"]
        return {t.node_id: a for t, a in zip(targets, answers)}

    async def open(self) -> list[Target]:
        """Reach every target once (its prompt); the unreachable are left out."""
        answers = await self._all({"line": ""})
        for target in list(self.targets):
            error = answers[target.node_id].get("error")
            if error:
                log(f"% {target.node_id}: {error}", LogLevel.ERROR)
                self.targets.remove(target)
        return self.targets

    async def close(self) -> None:
        await self._all({"close": True})

    async def completions(self, text: str) -> list[dict[str, str]]:
        """The remote console's candidates, and ``disconnect``, which is this console's."""
        found: list[dict[str, str]] = []
        if self.targets:
            answer = await self.fleet.send(self.targets[0], self.session, {"complete": text})
            found = list(answer.get("candidates") or [])
        typed = text.lstrip()
        if " " not in typed and "disconnect".startswith(typed):
            found.append({"value": "disconnect", "display": "disconnect",
                          "description": DISCONNECT_HELP, "start": str(-len(typed))})
        return found

    async def answer_question(self, typed: str) -> None:
        """``?`` on the first word: the remote console's commands, ``disconnect`` among them."""
        candidates = await self.completions(typed)
        if not candidates:
            log(f"% Unrecognized command: {typed.strip() or '?'}", LogLevel.ERROR)
            return
        width = max(len(c["display"]) for c in candidates)
        for candidate in candidates:
            emit(f"  {candidate['display'].ljust(width)}  {candidate['description']}".rstrip())

    def _print(self, answers: dict[str, dict[str, Any]], *, quiet: set[str]) -> None:
        for target in self.targets:
            answer = answers.get(target.node_id)
            if answer is None:
                continue
            if not self.single:
                emit(f"--- {target.node_id} {target.address}"
                     f"{' (USD ' + target.usdn + ')' if target.foreign else ''} ---")
            if answer.get("error"):
                log(f"% {target.node_id}: {answer['error']}", LogLevel.ERROR)
                continue
            if target.node_id in quiet:
                continue
            for text in answer.get("output", []):
                if text != _NOT_CONFIRMED:
                    emit(text)

    async def run(self, line: str) -> bool:
        """One line on every target; True when they all left their console."""
        answers = await self._all({"line": line})
        asking = [t for t in self.targets if answers[t.node_id].get("needs_confirm")]
        self._print(answers, quiet={t.node_id for t in asking})
        if asking:
            question = next((o for o in answers[asking[0].node_id].get("output", [])
                             if o != _NOT_CONFIRMED), line)
            if not self.single:
                question += f" [{len(asking)} node(s): {', '.join(t.node_id for t in asking)}]"
            if await get_confirm_prompt().ask(question):
                again = await self._all({"line": line, "confirm": True}, asking)
                answers.update(again)
                self._print(again, quiet=set())
            else:
                log(_NOT_CONFIRMED, LogLevel.ERROR)
        if not self.single:
            reached = sum(1 for a in answers.values() if not a.get("error"))
            emit(f"{reached}/{len(self.targets)} node(s) answered")
        reached = [a for a in answers.values() if not a.get("error")]
        return bool(reached) and all(a.get("exit") for a in reached)


async def enter(shell: "UsmdShell", line: str, actor: ActionActor) -> None:
    """``node <id>`` and ``on <targets> [<line>]`` typed at *shell*."""
    if actor.source == SOURCE:
        log("% A console lent to an operator does not reach further nodes [ARCH 12.5]",
            LogLevel.ERROR)
        return
    verb, _, rest = line.strip().partition(" ")
    try:
        if verb == "node":
            if len(rest.split()) != 1:
                raise OperateError("node <id|address>: the console of one node")
            targets = await FLEET.resolve([("node", rest.strip())])
            if not targets:
                raise OperateError(f"no node '{rest.strip()}' in reach")
            remote = Remote(targets)
            if await remote.open():
                shell.remote = remote
                emit(f"Console of {targets[0].node_id}: 'exit' or 'disconnect' to come back.")
            return
        selectors, command = parse_targets(rest)
        if not selectors:
            raise OperateError(USAGE)
        targets = await FLEET.resolve(selectors)
    except OperateError as exc:
        log(f"% {exc}", LogLevel.ERROR)
        return
    if not targets:
        log("% No node matches", LogLevel.ERROR)
        return
    remote = Remote(targets)
    if command:
        await remote.run(command)
        await remote.close()
        return
    if await remote.open():
        shell.remote = remote
        emit(f"Lines now go to {len(remote.targets)} node(s): "
             + ", ".join(t.node_id for t in remote.targets) + ". 'disconnect' to come back.")


async def remote_line(shell: "UsmdShell", line: str) -> None:
    """A line typed while the console is another node's (or several)."""
    remote = shell.remote
    assert remote is not None
    stripped = line.rstrip()
    if stripped.endswith("?") and " " not in stripped[:-1].strip() \
            and stripped.count('"') % 2 == 0:
        await remote.answer_question(stripped[:-1].strip())
        return
    if line.strip() == "disconnect":
        shell.remote = None
        await remote.close()
        emit("Back to the console of this node.")
        return
    if await remote.run(line):
        shell.remote = None
        await remote.close()
        emit("Back to the console of this node.")


async def run_form(selector: str, form: dict[str, Any]) -> dict[str, Any]:
    """A web configuration form applied on every target of *selector*."""
    targets = await _targets(selector)
    answers = await Remote(targets)._all({"form": form})  # pylint: disable=protected-access
    errors = [f"{n}: {a.get('error')}" for n, a in answers.items() if not a.get("ok")]
    return {"ok": not errors, "results": answers, "error": "; ".join(errors),
            "output": [f"{n}: {'applied' if a.get('ok') else a.get('error')}"
                       for n, a in answers.items()]}


async def schema_of(selector: str) -> dict[str, Any]:
    """The configuration forms of the first target of *selector*."""
    targets = await _targets(selector)
    answer = await FLEET.send(targets[0], 0, {"schema": True})
    if "error" in answer:
        raise OperateError(f"{targets[0].node_id}: {answer['error']}")
    return answer


async def _targets(selector: str) -> list[Target]:
    selectors, rest = parse_targets(selector)
    if not selectors or rest:
        raise OperateError(USAGE)
    targets = await FLEET.resolve(selectors)
    if not targets:
        raise OperateError("no node matches")
    return targets


async def overview() -> dict[str, Any]:
    """What the web target selector offers."""
    try:
        scope = FLEET.scope()
    except OperateError:
        scope = ""
    if not scope:
        return {"scope": "", "nodes": [], "usds": []}
    node = RUNTIME.node
    own = node.signed.usd.usdn if node.signed.usd else ""
    nodes = await FLEET.everyone(quiet=True)
    return {"scope": scope, "self": node.node_id, "usdn": own,
            "nodes": [t.row() for t in nodes],
            "usds": [own] + (FLEET.other_usds() if scope == "usc" else [])}
