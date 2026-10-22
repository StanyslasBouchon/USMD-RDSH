"""``config system``: hostname, logging and the management web interface."""

from typing import Annotated

from nan_actions.views import ConfigNode, view
from pydantic import BaseModel, Field

from usmd_rdsh.cli.logbuffer import SEVERITY_KEYWORDS
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.views.common import NODE_ACCESS, IPv4, LogLevel, Port


class GlobalConfig(BaseModel):
    """Node-wide settings."""

    hostname: str = Field("", description="Name shown in the prompt (default: usmd-<id>)")
    banner: str = Field("", description="Text printed when the console starts")


@view("system global", model=GlobalConfig, **NODE_ACCESS)
class GlobalView(ConfigNode):
    """Hostname and login banner."""


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


class WebInterfaceConfig(BaseModel):
    """The management web interface and the token API behind it."""

    status: bool = Field(False, description="Serve the web interface")
    listen_address: IPv4 = Field("127.0.0.1", description="Address to bind")
    port: Port = Field(8080, description="TCP port")
    tls_certificate: Annotated[str, Field(description="PEM certificate file (enables HTTPS)")] = ""
    tls_private_key: Annotated[str, Field(description="PEM private key file")] = ""
    refresh_interval: int = Field(5, ge=1, le=3600, description="Dashboard refresh, seconds")


@view("system web-interface", model=WebInterfaceConfig, **NODE_ACCESS)
class WebInterfaceView(ConfigNode):
    """Web management and monitoring interface; disable with 'set status disable'."""

    async def apply(self, config: WebInterfaceConfig) -> None:
        if bool(config.tls_certificate) != bool(config.tls_private_key):
            raise ValueError("set both tls-certificate and tls-private-key, or neither")
        if RUNTIME.web is not None:
            await RUNTIME.web.reconfigure(config)
