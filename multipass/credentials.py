"""Where credentials come from, and in what order.

Four sources, highest precedence first. Each field (username, password) is
resolved independently, so a username on the command line can pair with a
password from a prompt:

    1. explicit secret file    --secrets-file PATH   (--username for the name)
    2. environment variable    per `CredentialNames`
    3. default secrets file    a host-chosen path (e.g. under the state dir)
    4. interactive prompt      only when a controlling terminal exists

**There is deliberately no password flag at all** -- not `--password`, not
`--password-stdin`. OpenSSH is the barometer here: it offers no way to hand a
password to the process, because argv is not private (shell history, and
/proc/<pid>/cmdline is world-readable), and because a prompt plus `sshpass`
already covers the scripted case. If there is no password on hand, we simply
ask for it.

**sshpass interoperability.** sshpass drives a program over a pty, watches its
output for a prompt matching `assword`, and types the password when it appears.
Two details here exist to keep that working and must not be "tidied" away:

  * the password prompt text contains `Password:`
  * the prompt is read via `getpass`, which reads /dev/tty rather than stdin

The username must come from somewhere else under sshpass -- it answers only the
password prompt, so a username prompt would hang waiting for input that never
arrives. Use --username, a secrets file, or the environment.

**A password is not always needed.** Some identity providers treat an
authenticator app as the *primary* credential, so `require_password=False`
means the password is neither read nor prompted for -- `resolve_credentials`
reports its source as "not needed (passwordless)". That is a flag in the host
changing a requirement two layers down, which is a seam worth knowing about.
"""

from __future__ import annotations

import getpass
import io
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

#: Branding arrives per call, never as setup. A library must not hardcode its
#: first host's variable names, and every message below that names a variable,
#: a flag example, or a program reads them from the `CredentialNames` the
#: caller passed in. There is no active branding to configure and no default
#: to inherit: the provisional (`MULTIPASS_*`) object exists only so the shape
#: has something to show, not something to run under.
@dataclass(frozen=True)
class CredentialNames:
    """The host-specific spellings this module may utter."""

    username_vars: tuple[str, ...] = ("MULTIPASS_USERNAME",)
    password_vars: tuple[str, ...] = ("MULTIPASS_PASSWORD",)
    #: Named in the no-terminal error so the reader knows which program to run
    #: differently (sshpass, env, file). Not a binary lookup — just prose.
    program: str = "multipass"


#: Must contain "assword" -- sshpass matches on that substring by default, and
#: changing this wording silently breaks scripted runs.
PASSWORD_PROMPT = "  Password: "
USERNAME_PROMPT = "  Username: "


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or unusable."""


@dataclass(frozen=True)
class Resolved:
    """A value plus where it came from.

    The source is carried so runs can say *which* source was used without ever
    printing the value -- the single most useful thing when a login fails and
    three config mechanisms are in play.
    """

    value: str
    source: str


def parse_env_file(path: Path) -> dict[str, str]:
    """Read KEY=VALUE lines, ignoring comments and blanks."""
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip("'\"")
    return values


def warn_if_world_readable(path: Path) -> None:
    """Note a credentials file others can read. Advisory, not fatal."""
    if not path.exists():
        return
    mode = path.stat().st_mode
    if mode & (stat.S_IRGRP | stat.S_IROTH):
        print(
            f"WARNING: {path} is readable beyond its owner "
            f"(mode {stat.S_IMODE(mode):04o}). Run: chmod 600 {path}",
            file=sys.stderr,
        )


def tty_available() -> bool:
    """Whether a controlling terminal exists to prompt on.

    Deliberately *not* `sys.stdin.isatty()`. sshpass does not redirect stdin --
    it makes a pty the child's controlling terminal and answers whatever appears
    on /dev/tty, because that is where ssh reads its password from. Checking
    stdin instead refuses to prompt under sshpass and breaks the exact scripted
    case this design points people at.
    """
    try:
        fd = os.open("/dev/tty", os.O_RDWR)
    except OSError:
        return False
    os.close(fd)
    return True


def _read_from_tty(prompt: str) -> str:
    """Read a non-secret line from the controlling terminal.

    getpass handles this for passwords; usernames need the same treatment so a
    prompt still works when stdin is a pipe.

    Built the way getpass builds it, and for the same reason: plain
    `open("/dev/tty", "r+")` returns a buffered random-access stream, which
    demands seekability that a pty does not have -- it raises
    "File or stream is not seekable" the moment you use it under sshpass or any
    other pty driver. FileIO + TextIOWrapper sidesteps that.
    """
    fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    with io.FileIO(fd, "w+") as raw, io.TextIOWrapper(raw) as tty:
        tty.write(prompt)
        tty.flush()
        return tty.readline()


def _prompt(field: str, secret: bool, names: CredentialNames) -> str:
    """Ask the human, but only if there is a human to ask."""
    if not tty_available():
        var = names.password_vars[0] if secret else names.username_vars[0]
        options = [
            f"--secrets-file PATH    a file containing {var}=...",
            f"${var}    environment variable",
        ]
        # A username is not secret, so offering the flag is fine; a password has
        # no flag at all, so point at sshpass, which answers the prompt instead.
        if secret:
            options.insert(
                0, f"sshpass -p ... {names.program} ...    answers the prompt over a pty")
        else:
            options.insert(0, "--username VALUE")
        listed = "\n".join(f"  {opt}" for opt in options)
        raise ConfigError(
            f"No {field} available, and there is no controlling terminal to "
            f"prompt on.\nProvide it with one of:\n{listed}"
        )
    # getpass reads /dev/tty rather than stdin, which is both why the password is
    # never echoed and why sshpass (which drives us over a pty) can answer it.
    if secret:
        value = getpass.getpass(PASSWORD_PROMPT).strip()
    else:
        value = _read_from_tty(USERNAME_PROMPT).strip()
    if not value:
        raise ConfigError(f"No {field} entered.")
    return value


def resolve_credentials(
    *,
    names: CredentialNames,
    username: str | None = None,
    secrets_file: Path | None = None,
    default_file: Path,
    allow_prompt: bool = True,
    require_password: bool = True,
) -> tuple[Resolved, Resolved]:
    """Resolve (username, password), each independently, by precedence.

    `names` is required and has no default: the spellings are the host's
    identity, and a default here would be the thing every host silently
    inherits. There is nothing to configure first; the branding arrives with
    the call.

    `require_password=False` is for **passwordless sign-in**, where the
    identity provider treats an authenticator app as the primary credential.
    There is then no password to resolve, and demanding one would refuse a
    login that needs no secret at rest -- which is the whole point of it.
    """
    explicit_values: dict[str, str] = {}
    if secrets_file is not None:
        # Distinguish "wrong path" from "not a readable file" -- a typo'd path
        # and a directory are different mistakes and deserve different messages.
        if not secrets_file.exists():
            raise ConfigError(f"--secrets-file {secrets_file} does not exist.")
        if secrets_file.is_dir():
            raise ConfigError(f"--secrets-file {secrets_file} is a directory.")
        warn_if_world_readable(secrets_file)
        explicit_values = parse_env_file(secrets_file)

    warn_if_world_readable(default_file)
    default_values = parse_env_file(default_file)

    def resolve(
        field: str, spellings: tuple[str, ...], cli_value: str | None, secret: bool,
    ) -> Resolved:
        """One field, every source in precedence order, every spelling in each.

        The loop is over sources *outside* and spellings *inside*, which is what
        makes a second spelling a true alias: an environment variable still beats
        the secrets file whichever of the two names it is spelled with.
        """
        if cli_value:
            return Resolved(cli_value, "command line")
        sources = (
            (explicit_values, f"--secrets-file ({secrets_file})"),
            (os.environ, None),               # None: named per-variable below
            (default_values, f"{default_file}"),
        )
        for values, label in sources:
            for name in spellings:
                if values.get(name):
                    where = label if label else f"${name}"
                    if name != spellings[0]:
                        # Say so, so a working setup can be migrated at leisure
                        # rather than discovered to be legacy when it breaks.
                        where += f" [{name} is deprecated; use {spellings[0]}]"
                    return Resolved(values[name], where)
        if allow_prompt:
            return Resolved(_prompt(field, secret, names), "prompt")
        raise ConfigError(
            f"No {field} available and prompting is disabled (--no-prompt)."
        )

    return (
        resolve("username", names.username_vars, username, secret=False),
        resolve("password", names.password_vars, None, secret=True)
        if require_password
        else Resolved("", "not needed (passwordless)"),
    )


__all__ = [
    "CredentialNames",
    "ConfigError",
    "Resolved",
    "parse_env_file",
    "warn_if_world_readable",
    "tty_available",
    "resolve_credentials",
]
