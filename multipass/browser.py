"""Persistent browser session.

A persistent Playwright context rather than a fresh browser per run, so that
session cookies — the IdP's, and any "remember this device" second-factor
cookie — survive between invocations. Those cookies are the entire reason a
run can proceed without bothering the user.

The profile holds live credential-equivalent state. This module never chooses
where it lives: the host passes `profile_dir` and `session_file` in, and the
modes (700/600) are applied on every call, not just at creation.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
from collections.abc import Callable, Iterator
from datetime import datetime
from pathlib import Path

from playwright.sync_api import (
    BrowserContext,
    Error as PlaywrightError,
    Page,
    sync_playwright,
)

__all__ = [
    "BrowserUnavailable",
    "install_chromium",
    "open_context",
    "open_page",
    "save_debug_snapshot",
]


class BrowserUnavailable(RuntimeError):
    """Chromium could not be started, with an actionable reason."""


#: Roughly what `playwright install chromium` pulls down, for the prompt. Worth
#: naming: consenting to a download is different from consenting to a command.
DOWNLOAD_SIZE = "~150 MB"


def _install_hint() -> str:
    return (
        "Chromium is not installed. The `playwright` package on PyPI ships the "
        "library and its driver, but not the browser binaries -- those are a "
        "separate download, because they are platform-specific native builds "
        "rather than Python. Install them with:\n\n"
        "    python -m playwright install chromium\n\n"
        "in this interpreter's own environment."
    )


def _is_missing_browser(exc: Exception) -> bool:
    """Whether a launch failure means "no browser" rather than "launch broke".

    Matched on Playwright's own wording. Deliberately narrow: treating any
    launch failure as a missing browser would offer to download 150 MB in
    answer to a sandbox or permissions problem, which fixes nothing and looks
    like the tool guessing.
    """
    text = str(exc)
    return "Executable doesn't exist" in text or "playwright install" in text


def _launch_failure(exc: Exception) -> BrowserUnavailable:
    """Turn Playwright's launch error into something worth reading.

    Playwright's own message does say what to do, buried in a wall of text
    about drivers and revisions, so the instruction is hoisted to the front.
    """
    if _is_missing_browser(exc):
        return BrowserUnavailable(_install_hint())
    return BrowserUnavailable(f"could not start Chromium: {exc}")


def install_chromium(with_deps: bool = False) -> None:
    """Run Playwright's own installer for Chromium. **Downloads ~150 MB.**

    `sys.executable -m playwright` rather than a bare `playwright`: the CLI on
    PATH may belong to a different environment than the one importing this
    module -- a venv that was never activated, a pipx install, a system Python.
    Installing into the wrong one downloads 150 MB and changes nothing here.

    Output is not captured, so the user sees the real progress rather than a
    silent multi-minute pause.
    """
    command = [sys.executable, "-m", "playwright", "install"]
    if with_deps:
        # Needs root on most Linux distributions; only offered explicitly.
        command.append("--with-deps")
    command.append("chromium")

    print(f"  Running: {' '.join(command)}", file=sys.stderr)
    result = subprocess.run(command)
    if result.returncode != 0:
        raise BrowserUnavailable(
            f"`{' '.join(command)}` exited {result.returncode}. On Linux the "
            f"browser may also need system libraries: try "
            f"`python -m playwright install --with-deps chromium` (which needs root)."
        )


#: The bundled headless build advertises "HeadlessChrome", which is both an
#: unnecessary tell and a plausible trigger for bot-detection on the IdP. Present
#: as ordinary desktop Chrome instead.
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
)

VIEWPORT = {"width": 1440, "height": 900}


@contextlib.contextmanager
def open_context(
    *,
    profile_dir: Path,
    session_file: Path,
    headless: bool = True,
    slow_mo: int = 0,
    on_missing_browser=None,
    locale: str = "en-US",
    timezone_id: str = "America/New_York",
) -> Iterator[BrowserContext]:
    """Open the persistent browser context, creating the profile if needed.

    `profile_dir` and `session_file` are required and have no defaults: a
    library must not invent where credential-equivalent state lives, and a
    default here would be the thing every host silently inherits. The caller
    owns the paths; this module owns the modes.

    `on_missing_browser` is an optional callable invoked when the launch fails
    *because Chromium was never downloaded*. Returning True means it has been
    installed and the launch should be retried once. The decision to prompt and
    download lives with the caller, not here -- this module should not own the
    question of whether there is a human to ask.

    `locale` and `timezone_id` are what the pages render in. They default to
    the values this was built against; a host whose users live elsewhere
    should pass its own rather than inherit these silently.
    """
    profile_dir.mkdir(parents=True, exist_ok=True)
    profile_dir.chmod(0o700)

    def launch(p):
        return p.chromium.launch_persistent_context(
            user_data_dir=str(profile_dir),
            headless=headless,
            slow_mo=slow_mo,
            user_agent=USER_AGENT,
            viewport=VIEWPORT,
            locale=locale,
            timezone_id=timezone_id,
            args=["--disable-blink-features=AutomationControlled"],
        )

    with sync_playwright() as p:
        try:
            context = launch(p)
        except PlaywrightError as exc:
            # One retry, and only for a missing browser. If the install ran and
            # the launch still fails, report that failure rather than looping.
            if not (_is_missing_browser(exc) and on_missing_browser
                    and on_missing_browser()):
                raise _launch_failure(exc) from exc
            try:
                context = launch(p)
            except PlaywrightError as retry_exc:
                raise _launch_failure(retry_exc) from retry_exc
        context.set_default_timeout(30_000)
        _restore_session_cookies(context, session_file)
        try:
            yield context
        finally:
            # Save before close: storage_state() needs a live context.
            _save_session_cookies(context, session_file)
            context.close()


def _restore_session_cookies(context: BrowserContext, session_file: Path) -> None:
    """Re-inject cookies saved from a previous run.

    A persistent profile is *not* sufficient on its own: session cookies are
    typically non-persistent, so Chromium drops them the moment the browser
    closes, while "remember this device" cookies survive. Saving and
    re-injecting the session ourselves is what makes a login last beyond a
    single process.
    """
    if not session_file.is_file():
        return
    try:
        cookies = json.loads(session_file.read_text()).get("cookies", [])
    except (OSError, ValueError):
        return  # A corrupt cache is not worth failing a run over; just re-login.
    if cookies:
        with contextlib.suppress(Exception):
            context.add_cookies(cookies)


def _save_session_cookies(context: BrowserContext, session_file: Path) -> None:
    """Persist cookies, including the session cookies Chromium would discard.

    The file is credential-equivalent -- it grants access without a password --
    so it lives wherever the host put it, at mode 600, never in the working
    directory.
    """
    try:
        state = context.storage_state()
    except Exception:
        return
    session_file.parent.mkdir(parents=True, exist_ok=True)
    session_file.parent.chmod(0o700)
    session_file.write_text(json.dumps(state))
    session_file.chmod(0o600)


@contextlib.contextmanager
def open_page(**kwargs) -> Iterator[Page]:
    """Convenience wrapper yielding a single page from a persistent context."""
    with open_context(**kwargs) as context:
        page = context.pages[0] if context.pages else context.new_page()
        yield page


#: Decides whether a page must not be rendered to disk. Returns the reasons,
#: or nothing when the page may be captured. Injected because sensitivity is
#: host policy: one host's gradebook is another's expense report, and a gate
#: whose table lives here would judge every host by the first host's data.
#: `None` (the default) captures everything — a host with anything to protect
#: must inject its own, or it has no gate at all.
WithholdGate = Callable[[Page], tuple[str, ...] | None]


def save_debug_snapshot(
    page: Page,
    label: str,
    directory: Path,
    *,
    why_withhold: WithholdGate | None = None,
) -> Path:
    """Dump a screenshot and the page HTML for diagnosing a stuck flow.

    Headless means we cannot simply look at the screen, so anything that fails
    in an unexpected place needs to leave evidence behind.

    `directory` is required and has no default, for the same reason the profile
    path has none: snapshots render whole authenticated pages, so the mode-700
    directory they land in is the host's decision, not this module's.

    This is the one place the withhold decision is made, which is what keeps
    every call site free of it: a caller that had to remember to ask would be
    one refactor from a caller that forgot.
    """
    directory.mkdir(parents=True, exist_ok=True)
    # `mkdir` takes the umask, which is 022 on a stock machine. Applied on
    # EVERY call, not just at creation, because a directory made by an older
    # build (or by a `parents=True` walk) is already wrong and would never be
    # corrected otherwise. Do not rely on the parent for this: a state dir has
    # no guaranteed mode anywhere.
    directory.chmod(0o700)
    stem = directory / label

    # Asked BEFORE anything is written, not cleaned up afterwards. A render
    # that reaches disk and is deleted has still been on disk, and on a machine
    # where the directory is world-readable it has been there world-readable
    # for the width of that window.
    withheld = why_withhold(page) if why_withhold else None
    if withheld:
        return _withhold(stem, label, page, withheld)

    page.screenshot(path=f"{stem}.png", full_page=True)
    Path(f"{stem}.html").write_text(page.content())
    for path in (Path(f"{stem}.png"), Path(f"{stem}.html")):
        path.chmod(0o600)
    return Path(f"{stem}.png")


def _withhold(stem: Path, label: str, page: Page, reasons: tuple[str, ...]) -> Path:
    """Record that a snapshot was deliberately not taken, and why.

    The URL is included: it names the route and the ids, which is what makes
    the failure locatable. Nothing is read out of the page itself -- that is
    the whole point.
    """
    try:
        url = page.url
    except PlaywrightError:  # pragma: no cover - the fail-closed path's own edge
        url = "(could not be read)"
    path = Path(f"{stem}.txt")
    path.write_text(
        f"snapshot WITHHELD -- this page carries data the host "
        f"asked never to render to disk.\n"
        f"label:  {label}\n"
        f"when:   {datetime.now().astimezone().isoformat(timespec='seconds')}\n"
        f"url:    {url}\n"
        f"why:    {'; '.join(reasons)}\n"
        "\n"
        "No screenshot or HTML was written.\n"
    )
    path.chmod(0o600)
    return path
