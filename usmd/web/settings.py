"""Django settings for the USMD-RDSH web dashboard.

Settings are configured dynamically at runtime (no on-disk settings module),
allowing the web server to inherit values from NodeConfig.

This module is NOT imported directly by Django — call configure() first,
which calls django.conf.settings.configure().

Examples:
    >>> # In WebServer.start():
    >>> from usmd.web.settings import configure
    >>> configure(username="admin", password="secret", secret_key="abc...")
"""

from __future__ import annotations

from pathlib import Path

# Directory that contains this file — used to build template and static paths.
_WEB_DIR = Path(__file__).parent


def configure(
    username: str,
    password: str,
    secret_key: str,
    debug: bool = False,
) -> None:
    """Configure Django settings in-process.

    Must be called before any Django module is imported.

    Args:
        username: Web dashboard login username.
        password: Web dashboard login password.
        secret_key: Django SECRET_KEY (random string, generated at startup).
        debug: Enable Django debug mode (disabled in production).
    """
    from django.conf import settings  # pylint: disable=import-outside-toplevel

    if settings.configured:
        return  # Already configured (idempotent)

    settings.configure(
        DEBUG=debug,
        SECRET_KEY=secret_key,
        ALLOWED_HOSTS=["*"],
        # ---- Apps --------------------------------------------------------
        INSTALLED_APPS=[
            "django.contrib.staticfiles",
            "django.contrib.sessions",
        ],
        # ---- Middleware ---------------------------------------------------
        MIDDLEWARE=[
            "django.middleware.security.SecurityMiddleware",
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.middleware.common.CommonMiddleware",
            "django.middleware.csrf.CsrfViewMiddleware",
            "django.middleware.clickjacking.XFrameOptionsMiddleware",
        ],
        # ---- Sessions (no database — signed cookies) ---------------------
        SESSION_ENGINE="django.contrib.sessions.backends.signed_cookies",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # ---- URL routing -------------------------------------------------
        ROOT_URLCONF="usmd.web.urls",
        # ---- Templates ---------------------------------------------------
        TEMPLATES=[
            {
                "BACKEND": "django.template.backends.django.DjangoTemplates",
                "DIRS": [str(_WEB_DIR / "templates")],
                "APP_DIRS": False,
                "OPTIONS": {
                    "context_processors": [
                        "django.template.context_processors.request",
                    ],
                },
            }
        ],
        # ---- Static files ------------------------------------------------
        STATIC_URL="/static/",
        STATICFILES_DIRS=[str(_WEB_DIR / "static")],
        # ---- No database -------------------------------------------------
        DATABASES={},
        # ---- ASGI app ----------------------------------------------------
        ASGI_APPLICATION="usmd.web.asgi.application",
        # ---- Custom web credentials (accessible from views via settings) --
        USMD_WEB_USERNAME=username,
        USMD_WEB_PASSWORD=password,
        # ---- Logging — do not let Django override the daemon's logging setup ---
        LOGGING_CONFIG=None,
        # ---- Security ----------------------------------------------------
        SECURE_CONTENT_TYPE_NOSNIFF=True,
        X_FRAME_OPTIONS="DENY",
    )

    # Create static dir if absent (won't fail if directory already exists)
    (Path(_WEB_DIR) / "static").mkdir(exist_ok=True)
