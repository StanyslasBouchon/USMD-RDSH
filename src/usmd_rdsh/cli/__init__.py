"""Management plane of a USMD-RDSH node: console, configuration tree and logging.

The console is built on ``nan_actions``:

    - every read-only or operational command (``show ...``, ``clear ...``,
      ``execute ...``) is an ``@action`` in ``usmd_rdsh.cli.actions``, which also
      makes it reachable from the token API the web interface uses;
    - every configurable value is a node of the view tree declared in
      ``usmd_rdsh.cli.views`` and walked with ``config`` / ``set`` / ``end``.
"""
