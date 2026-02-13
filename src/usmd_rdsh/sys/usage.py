"""System usage information."""

import psutil
from usmd_rdsh.utils.result import Result
from usmd_rdsh.utils.errors import Error


def get_cpu_usage() -> Result[float, Error]:
    """Get the CPU usage as a percentage."""
    return Result.Ok(psutil.cpu_percent())


def get_memory_usage() -> Result[float, Error]:
    """Get the memory usage as a percentage."""
    return Result.Ok(psutil.virtual_memory().percent)


def get_disk_usage() -> Result[float, Error]:
    """Get the disk usage as a percentage."""
    return Result.Ok(psutil.disk_usage("/").percent)


def get_network_usage() -> Result[int, Error]:
    """Get the network usage as bytes sent and received."""
    return Result.Ok(
        psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
    )


def get_all_usage() -> Result[dict[str, float | int], Error]:
    """Get all usage information."""
    return Result.Ok(
        {
            "cpu": get_cpu_usage(),
            "memory": get_memory_usage(),
            "disk": get_disk_usage(),
            "network": get_network_usage(),
        }
    )
