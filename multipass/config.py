"""State locations and host branding.

Secrets, the saved session, and the browser profile live in one per-user state
directory and **never in the working directory** -- keeping them physically
outside any repo means they cannot be committed by accident.

Where that directory is depends on the machine (`resolve_state_dir`):

    $MULTIPASS_HOME                        explicit, wins outright
    %LOCALAPPDATA%\\<app>                   Windows
    ~/Library/Application Support/<app>    macOS
    $XDG_STATE_HOME/<app>                  otherwise (~/.local/state/<app>)

The platform directory is the default, always. A machine that wants a
different location says so with the override variable, which is explicit and
needs no rule to explain it.

Branding — the variable names, the app dirname, the program name — arrives as
one frozen `AuthConfig` value that the host constructs and passes in. There is
no `apply()`, no active branding, nothing to configure first: the struct is
the library's shape, the values are the host's setup. `StatePaths` needs the
same object to name the three files, so one construction serves both.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

from .credentials import CredentialNames

__all__ = [
    "AuthConfig",
    "StatePaths",
    "resolve_state_dir",
]


@dataclass(frozen=True)
class AuthConfig:
    """Everything about the host application this package may utter.

    One object, constructed once, replacing every hardcoded program name, env
    var, dirname, and filename the port would otherwise have carried over.
    """

    #: Shown in install hints and error prose. Not a binary lookup — just words.
    program: str = "multipass"
    #: The one override. Everything else is the platform's own answer.
    home_var: str = "MULTIPASS_HOME"
    #: Directory name under the platform state dir (and the default env file
    #: stem): `~/.local/state/<app_dir>/<env_filename>`.
    app_dir: str = "multipass"
    #: Secrets-file name inside the state dir.
    env_filename: str = "multipass.env"
    #: Browser-profile directory name inside the state dir. It holds live
    #: session cookies: exactly as sensitive as the password.
    profile_dirname: str = "browser-profile"
    #: Saved-cookie filename inside the state dir. Credential-equivalent: it
    #: grants access with no password. Mode 600, never the working directory.
    session_filename: str = "storage_state.json"
    #: Where a non-default login entry path is configured, resolved like a URL.
    sso_path_var: str = "MULTIPASS_SSO_PATH"
    #: The credential spellings. See `credentials.CredentialNames`. Passed
    #: through to `resolve_credentials` and the login prose -- never read from
    #: here by any module directly.
    names: CredentialNames = CredentialNames(
        username_vars=("MULTIPASS_USERNAME",),
        password_vars=("MULTIPASS_PASSWORD",),
    )


def resolve_state_dir(config: AuthConfig) -> Path:
    """Where the session, browser profile, and secrets file live.

    `config` is required and has no default: everything under here is
    credential-equivalent, and a defaulted location would be the thing every
    host silently inherits. The caller owns the decision; this function owns
    the platform mapping.

    Everything under here is credential-equivalent, so it is never the working
    directory and never the installed package. It is per-user state, and it
    goes where the platform puts per-user state.
    """
    override = os.environ.get(config.home_var)
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local"
        return Path(base) / config.app_dir
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / config.app_dir
    # XDG. `state` rather than `config` or `cache`: this is data the program
    # writes and needs back, and losing it costs a re-login.
    base = os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state"
    return Path(base) / config.app_dir


@dataclass(frozen=True)
class StatePaths:
    """Where one profile's state lives: the same three things, same names."""

    root: Path
    config: AuthConfig = AuthConfig()

    @property
    def env_file(self) -> Path:
        return self.root / self.config.env_filename

    @property
    def profile_dir(self) -> Path:
        return self.root / self.config.profile_dirname

    @property
    def session_state_file(self) -> Path:
        return self.root / self.config.session_filename
