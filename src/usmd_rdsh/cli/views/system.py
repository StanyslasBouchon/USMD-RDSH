"""``config system``: hostname, logging and the management web interface."""

import ipaddress
from enum import StrEnum
from typing import Annotated

from nan_actions.views import ConfigNode, Secret, view
from pydantic import BaseModel, Field, field_validator

from usmd_rdsh.cli.logbuffer import SEVERITY_KEYWORDS
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.views.common import NODE_ACCESS, IPv4, LogLevel, Port


class GlobalConfig(BaseModel):
    """Node-wide settings."""

    hostname: str = Field("", description="Name shown in the prompt (default: usmd-<id>)")
    banner: str = Field("", description="Text printed when the console starts")
    address: str = Field("auto", description="IPv4 of this node, or auto (outbound interface)")

    @field_validator("address")
    @classmethod
    def _address(cls, value: str) -> str:
        if value != "auto":
            ipaddress.IPv4Address(value)  # IPv4 only [ARCH 3.5]
        return value


@view("system global", model=GlobalConfig, **NODE_ACCESS)
class GlobalView(ConfigNode):
    """Hostname, login banner and the node's address."""

    async def apply(self, config: GlobalConfig) -> None:
        node = RUNTIME.node
        if node is not None and config.address != "auto":
            node.settings.address = config.address


class LoggingConfig(BaseModel):
    """Where syslog messages go, Cisco style."""

    status: bool = Field(True, description="Log at all")
    buffered_size: int = Field(4096, ge=16, le=100000, description="Messages kept")
    buffered_level: LogLevel = Field(LogLevel.DEBUGGING, description="Lowest level buffered")
    console: bool = Field(True, description="Copy messages to the console")
    console_level: LogLevel = Field(LogLevel.WARNINGS, description="Lowest level on console")
    timestamp_msec: bool = Field(True, description="Milliseconds in timestamps")
    sequence_numbers: bool = Field(False, description="Number every message")


@view("system logging", model=LoggingConfig, **NODE_ACCESS)
class LoggingView(ConfigNode):
    """Logging buffer, console logging and timestamps."""

    async def apply(self, config: LoggingConfig) -> None:
        buffer = RUNTIME.logbuffer
        buffer.enabled = config.status
        buffer.resize(config.buffered_size)
        buffer.buffered_level = SEVERITY_KEYWORDS[str(config.buffered_level)]
        buffer.console_level = SEVERITY_KEYWORDS[str(config.console_level)]
        buffer.console_enabled = config.console
        buffer.timestamp_msec = config.timestamp_msec
        buffer.sequence_numbers = config.sequence_numbers


class TlsMode(StrEnum):
    """HTTPS of the web interface."""

    OFF = "off"
    SELF_SIGNED = "self-signed"
    FILES = "files"


class WebInterfaceConfig(BaseModel):
    """The management web interface and the token API behind it."""

    status: bool = Field(False, description="Serve the web interface")
    listen_address: IPv4 = Field("127.0.0.1", description="Address to bind")
    port: Port = Field(8080, description="TCP port")
    tls_mode: TlsMode = Field(TlsMode.OFF, description="off, self-signed, or files")
    tls_certificate: Annotated[str, Field(description="PEM certificate file (tls-mode files)")] = ""
    tls_private_key: Annotated[str, Field(description="PEM private key file")] = ""
    username: str = Field("", description="Login of the web form (empty: tokens only)")
    password: Annotated[str, Secret] = Field("", description="Its password")
    refresh_interval: int = Field(5, ge=1, le=3600, description="Dashboard refresh, seconds")


class ServiceHostConfig(BaseModel):
    """How this node runs the commands of service files."""

    run_as: str = Field("", description="Unprivileged user running service commands (POSIX)")
    data_paths: list[str] = Field(
        [], description="service=path pairs: data of dynamic services (V of Tm)")
    volumes: list[str] = Field([], description="Volumes the services use (disk rate)")


@view("system service-host", model=ServiceHostConfig, **NODE_ACCESS)
class ServiceHostView(ConfigNode):
    """Privileges, data paths and volumes of hosted services [ARCH 6.1, 7.1, 14]."""

    async def apply(self, config: ServiceHostConfig) -> None:
        node = RUNTIME.node
        pairs = {}
        for item in config.data_paths:
            name, sep, path = item.partition("=")
            if not sep or not name or not path:
                raise ValueError(f"'{item}' is not service=path")
            pairs[name] = path
        if node is not None:
            node.settings.service_data = pairs
            node.runner.run_as = config.run_as or None
            node.load.volumes = list(config.volumes) or ["/"]


@view("system web-interface", model=WebInterfaceConfig, **NODE_ACCESS)
class WebInterfaceView(ConfigNode):
    """Web management and monitoring interface; disable with 'set status disable'."""

    async def apply(self, config: WebInterfaceConfig) -> None:
        if bool(config.tls_certificate) != bool(config.tls_private_key):
            raise ValueError("set both tls-certificate and tls-private-key, or neither")
        if config.tls_certificate and config.tls_mode == TlsMode.OFF:
            config = config.model_copy(update={"tls_mode": TlsMode.FILES})
        if config.tls_mode == TlsMode.FILES and not config.tls_certificate:
            raise ValueError("tls-mode files needs tls-certificate and tls-private-key")
        if bool(config.username) != bool(config.password):
            raise ValueError("set both username and password, or neither")
        if RUNTIME.web is not None:
            await RUNTIME.web.reconfigure(config)
