"""Reusable browser-login building blocks: credentials first, the rest to follow."""

from .auth import (
    IDPS,
    SHIBBOLETH,
    IdP,
    LoginError,
    LoginState,
    LoginTarget,
    MAX_LOGIN_STEPS,
    RECOGNISERS,
    Recogniser,
    ensure_logged_in,
    is_logged_in,
    log_in,
)
from .browser import (
    BrowserUnavailable,
    install_chromium,
    open_context,
    open_page,
    save_debug_snapshot,
)
from .config import AuthConfig, StatePaths, resolve_state_dir
from .credentials import (
    ConfigError,
    CredentialNames,
    Resolved,
    parse_env_file,
    resolve_credentials,
    tty_available,
    warn_if_world_readable,
)
from .entra import ENTRA, EntraPack, entra_pack

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "AuthConfig",
    "StatePaths",
    "resolve_state_dir",
    "ENTRA",
    "EntraPack",
    "entra_pack",
    "IdP",
    "IDPS",
    "SHIBBOLETH",
    "LoginError",
    "LoginTarget",
    "LoginState",
    "MAX_LOGIN_STEPS",
    "RECOGNISERS",
    "Recogniser",
    "ensure_logged_in",
    "is_logged_in",
    "log_in",
    "BrowserUnavailable",
    "install_chromium",
    "open_context",
    "open_page",
    "save_debug_snapshot",
    "ConfigError",
    "CredentialNames",
    "Resolved",
    "parse_env_file",
    "resolve_credentials",
    "tty_available",
    "warn_if_world_readable",
]
