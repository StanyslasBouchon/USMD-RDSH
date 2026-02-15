"""System usage information.

This module provides functions to retrieve CPU, memory, disk, and network
usage via psutil. All functions return Result[value, Error].
"""

import psutil

from usmd_rdsh.utils.errors import Error
from usmd_rdsh.utils.result import Result


def get_cpu_usage() -> Result[float, Error]:
    """Get the CPU usage as a percentage (0–100).

    Returns:
        Result[float, Error]: Ok(percent) on success, Err on failure.

    Example:
        >>> res = get_cpu_usage()
        >>> if res.is_ok():
        ...     print(f"CPU: {res.unwrap():.1f}%")
    """
    return Result.Ok(psutil.cpu_percent())


def get_memory_usage() -> Result[float, Error]:
    """Get the memory usage as a percentage of total RAM (0–100).

    Returns:
        Result[float, Error]: Ok(percent) on success, Err on failure.

    Example:
        >>> res = get_memory_usage()
        >>> if res.is_ok():
        ...     print(f"Memory: {res.unwrap():.1f}%")
    """
    return Result.Ok(psutil.virtual_memory().percent)


def get_disk_usage() -> Result[float, Error]:
    """Get the disk usage of the root filesystem as a percentage (0–100).

    Returns:
        Result[float, Error]: Ok(percent) on success, Err on failure.

    Example:
        >>> res = get_disk_usage()
        >>> if res.is_ok():
        ...     print(f"Disk: {res.unwrap():.1f}%")
    """
    return Result.Ok(psutil.disk_usage("/").percent)


def get_network_usage() -> Result[int, Error]:
    """Get the network I/O as total bytes sent + received since boot.

    Returns:
        Result[int, Error]: Ok(total_bytes) on success, Err on failure.

    Example:
        >>> res = get_network_usage()
        >>> if res.is_ok():
        ...     print(f"Network: {res.unwrap()} bytes")
    """
    return Result.Ok(
        psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
    )


def get_all_usage() -> Result[dict[str, float | int], Error]:
    """Get all usage metrics (CPU, memory, disk, network).

    Returns:
        Result[dict, Error]: Ok(dict) with keys "cpu", "memory", "disk",
                             "network". Values are Result objects; call .unwrap()
                             on each to get the raw value.

    Example:
        >>> res = get_all_usage()
        >>> if res.is_ok():
        ...     d = res.unwrap()
        ...     cpu_res = d["cpu"]
        ...     if cpu_res.is_ok():
        ...         print(f"CPU: {cpu_res.unwrap()}%")
    """
    return Result.Ok(
        {
            "cpu": get_cpu_usage(),
            "memory": get_memory_usage(),
            "disk": get_disk_usage(),
            "network": get_network_usage(),
        }
    )
