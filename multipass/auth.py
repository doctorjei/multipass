"""SSO login and session liveness: the recogniser loop and the standard states.

A login is driven as a **recogniser loop, not a sequence**: a set of page
states, each with a detector and an answer, dispatched against whatever is on
screen until authenticated or nothing matches. No state knows its index, so
three factors, one, or none is one code path, and a provider that inserts a
screen needs a row rather than a re-plumbing.

What lives here is the engine plus the standard states: a single-screen
username+password form (Shibboleth shape) and a Duo challenge (answered
through `duo-pass`, the default built-in factor plugin). Anything else — a
two-screen flow, a credential picker, a verification-method menu — arrives as
**plugin recognisers** via `extra_recognisers`, which dispatch through the
same loop with the same once-each guard. Core never names them.

Liveness is an allowlist of one host: authenticated iff the landing host
equals the configured home host, compared on the parsed hostname rather than
by substring.

The host supplies everything location- or brand-shaped: the SSO entry URL and
home host (`LoginTarget`), the credential values, the snapshot directory, and
the optional withhold gate. This module invents no paths and no names.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import NoReturn
from urllib.parse import urlsplit

from playwright.sync_api import (Error as PlaywrightError, Page,
                                 TimeoutError as PlaywrightTimeout)

from duo_pass import Approver, PushApprover, complete_duo, on_duo_page

from .browser import save_debug_snapshot
from .browser import WithholdGate
from .credentials import CredentialNames

__all__ = [
    "Approver",
    "PushApprover",
    "IdP",
    "IDPS",
    "SHIBBOLETH",
    "LoginError",
    "LoginTarget",
    "LoginState",
    "Recogniser",
    "RECOGNISERS",
    "MAX_LOGIN_STEPS",
    "quiesce",
    "is_logged_in",
    "log_in",
    "ensure_logged_in",
    "detect_idp",
]


@dataclass(frozen=True)
class IdP:
    """One identity-provider family's credential form.

    **A table, because the set grows.** A second family arrives as a plugin
    recogniser set plus a row here — never as a branch scattered through the
    engine.
    """

    #: What to call it in an error message a person has to act on.
    name: str
    username_field: str
    password_field: str
    submit: str
    #: Whether the username is submitted **on its own**, before the password
    #: box becomes usable. Not cosmetic: it decides whether a username box and
    #: a password box are one state or two.
    two_screen: bool
    #: Every selector that identifies this family, not just its username box.
    #: **An IdP that remembers the account never shows a username field at
    #: all**, so identifying a family only by the box you type a name into
    #: makes a remembered account unrecognisable.
    markers: tuple[str, ...] = ()


#: Every IdP family the core can drive. **Order is not significance** --
#: detection matches on the page's own controls and refuses when more than one
#: row could apply, so adding a row cannot silently re-route an existing host.
IDPS: tuple[IdP, ...] = (
    # `j_username`/`j_password` are JAAS names, one provider's convention --
    # which is exactly why they could never have been a default.
    IdP(name="Shibboleth",
        username_field="input[name='j_username']",
        password_field="input[name='j_password']",
        submit="button[name='_eventId_proceed']",
        two_screen=False,
        markers=("input[name='j_username']", "input[name='j_password']")),
)

#: The Shibboleth row's selectors, kept under their original names because they
#: are what error messages refer to.
SHIBBOLETH = IDPS[0]
USERNAME_FIELD = SHIBBOLETH.username_field
PASSWORD_FIELD = SHIBBOLETH.password_field
SUBMIT_BUTTON = SHIBBOLETH.submit


class LoginError(RuntimeError):
    """Raised when authentication cannot be completed."""


@dataclass(frozen=True)
class LoginTarget:
    """Where to start logging in, and what counts as logged in."""

    #: The login entry URL (the SSO route), gone to directly.
    sso_url: str
    #: The host that means "authenticated" when we land on it. Compared on the
    #: parsed hostname, never by substring.
    home_host: str
    #: Where snapshots land on failure. Required, no default: snapshots render
    #: whole authenticated pages, so their directory is the host's decision.
    snapshot_dir: Path
    #: How the module names credential variables in error prose. Required,
    #: no default: the spellings are the host's identity, and a default here
    #: would be the thing every host silently inherits.
    names: CredentialNames
    #: Sensitivity gate for snapshots. `None` captures everything — a host with
    #: anything to protect must pass its own, or it has no gate at all.
    why_withhold: WithholdGate | None = None


def host_of(url: str) -> str:
    """The bare hostname of a URL, lowercased. One parser for every check."""
    parsed = urlsplit(url if "//" in url else f"https://{url}")
    return (parsed.hostname or "").lower()


def _log(message: str) -> None:
    print(f"  {message}", file=sys.stderr, flush=True)


def _settle(page: Page, timeout_ms: int = 15_000) -> None:
    """Let the page finish loading, without demanding network silence.

    `networkidle` is the wrong tool anywhere Duo may be involved: Duo holds a
    long-poll connection open while it waits for the user to tap approve, so the
    network never goes idle and the wait times out *mid-login* -- killing the
    flow during the exact window the human is being asked to act.

    A timeout here is not fatal; the caller's own URL/selector checks decide
    whether we actually got where we meant to go.
    """
    try:
        page.wait_for_load_state("load", timeout=timeout_ms)
    except PlaywrightTimeout:
        pass


def quiesce(page: Page, timeout_ms: int = 15_000) -> None:
    """Wait for network idle where it genuinely helps, but never block on it.

    The IdP page does a client-side navigation shortly after load, so touching
    the DOM too early destroys the evaluation context. Waiting for idle avoids
    that -- but idle is not guaranteed to arrive, so a timeout is tolerated
    rather than raised. See `_settle` for why this matters on Duo.
    """
    try:
        page.wait_for_load_state("networkidle", timeout=timeout_ms)
    except PlaywrightTimeout:
        pass


def is_logged_in(page: Page, target: LoginTarget) -> bool:
    """Return whether the persistent session still has us authenticated."""
    page.goto(target.sso_url, wait_until="domcontentloaded")
    quiesce(page)
    return _looks_authenticated(page.url, target)


def _looks_authenticated(url: str, target: LoginTarget) -> bool:
    """Whether this URL means we are logged in to THIS host.

    **An allowlist of one host**, not a denylist of the places we might have
    been sent.
    """
    return host_of(url) == target.home_host


#: Is any of these password boxes one a PERSON could actually type into?
#:
#: **Not `element.isVisible()`, and that distinction is measured.** A parked,
#: invisible password box -- `opacity: 0`, `aria-hidden`, a few pixels in a
#: corner -- is called visible by Playwright, because it asks only about a
#: bounding box, `display` and `visibility`. A predicate built on that reads
#: "the password form is still up" on a screen where no password field is on
#: show at all. Typing into such a box raises nothing at all.
#:
#: Opacity is checked up the whole ancestor chain: a fully opaque input inside
#: a zeroed-out parent is invisible, and that is exactly how providers park
#: the view they are not currently showing.
OPERABLE_PASSWORD = """
(selectors) => {
  const operable = (sel) => {
    const e = document.querySelector(sel);
    if (!e || e.disabled) return false;
    if (e.getAttribute('aria-hidden') === 'true') return false;
    const r = e.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    for (let n = e; n; n = n.parentElement) {
      const cs = getComputedStyle(n);
      if (cs.display === 'none' || cs.visibility === 'hidden') return false;
      if (parseFloat(cs.opacity) === 0) return false;
    }
    return true;
  };
  return selectors.some(operable);
}
"""

#: True once no credential form the user could still be looking at remains.
#: That is the STRUCTURAL signal that primary authentication was accepted: an
#: IdP re-presents its own form when it rejects a password and moves on when it
#: does not.
#:
#: **One question, one implementation.** Asking whether the password input is
#: absent from the DOM is true of providers that remove the field and false of
#: ones that keep it hidden -- two predicates for one question is the shape
#: that has cost three separate bugs. The test is instead "is it *operable*",
#: correct for both, since an absent field is not operable either.
NO_OPERABLE_PASSWORD = f"""
(selectors) => !({OPERABLE_PASSWORD})(selectors)
"""


def detect_idp(page: Page, timeout_ms: int = 30_000,
               idps: tuple[IdP, ...] = IDPS) -> IdP:
    """Which IdP family's form is on screen.

    **Decided by the page's own controls, never by the host**, and it
    **refuses when unsure** rather than picking. Submitting a password to a
    form we have misidentified is the one mistake in this file worth refusing
    outright.
    """
    any_marker = ", ".join(m for idp in idps for m in idp.markers)
    try:
        # **`state="attached"`, and the default would be a bug.** A
        # comma-separated CSS list resolves to the FIRST match in DOM order,
        # and `wait_for_selector` waits for *visibility* by default -- so a
        # hidden early match blocks the wait while the visible answer sits
        # further down. Identifying a family is a question about PRESENCE,
        # not visibility.
        page.wait_for_selector(any_marker, timeout=timeout_ms, state="attached")
    except PlaywrightTimeout as exc:
        raise LoginError(
            f"The SSO login form never appeared (url={page.url}). Looked for "
            f"{', '.join(idp.name for idp in idps)}. If this host uses a "
            f"different identity provider, it needs a plugin recogniser set "
            f"and a new row in `IDPS`."
        ) from exc

    matched = [idp for idp in idps
               if any(page.locator(m).count() for m in idp.markers)]
    if len(matched) != 1:
        named = ", ".join(idp.name for idp in matched) or "none"
        raise LoginError(
            f"Could not tell which identity provider this is (url={page.url}); "
            f"matched: {named}. Refusing rather than guessing -- credentials "
            f"must not be typed into a form we have misidentified."
        )
    return matched[0]


def _submit_single_screen(page: Page, username: str, password: str,
                          idp: IdP) -> None:
    """Both fields and one click -- the single-screen shape, proven live."""
    page.fill(idp.username_field, username)
    page.fill(idp.password_field, password)
    page.click(idp.submit)
    page.wait_for_load_state("domcontentloaded")


#: Words an IdP uses when it turns credentials down. **These no longer decide
#: anything** -- they are used to quote the page back to the user. Deciding by
#: wording meant only one provider's phrasing was ever recognised.
#: **Widening this is safe precisely because it decides nothing** -- it only
#: chooses which of the page's own sentences is worth quoting back.
REJECTION_WORDS = ("incorrect", "invalid", "failed", "try again", "locked",
                   "unsuccessful", "not recognized", "again",
                   "couldn't find", "could not find", "doesn't exist",
                   "does not exist")


def _idp_complaint(page: Page) -> str:
    """Whatever the IdP says about the rejection, if it says anything.

    Best-effort and never load-bearing: an IdP that explains itself gets
    quoted, and one that does not still produces a clear error.
    """
    try:
        lines = page.evaluate(
            """() => Array.from(document.querySelectorAll(
                   '.alert, .form-error, [role=alert], .output--error, p, span'))
                 .map(e => (e.innerText || '').trim())
                 .filter(t => t && t.length < 200)""")
    except PlaywrightError:
        return ""
    for line in lines or []:
        low = line.lower()
        if any(word in low for word in REJECTION_WORDS):
            return line
    return ""


def _snapshot(state: LoginState, label: str) -> Path:
    """One call site for every failure snapshot: directory and gate included."""
    return save_debug_snapshot(state.page, label, state.target.snapshot_dir,
                               why_withhold=state.target.why_withhold)


def _check_for_credential_rejection(
    page: Page, target: LoginTarget, username: str, password: str,
    timeout_ms: int = 20_000, idp: IdP | None = None,
    idps: tuple[IdP, ...] = IDPS,
) -> None:
    """Fail fast and clearly on bad credentials, rather than timing out later.

    Worth being decisive: repeatedly submitting a wrong password is how
    accounts get locked out, which is far worse than an early error.

    **The signal is structural, not textual** -- the credential form either
    survives the submission or it does not. That works at any provider of the
    same shape, including one whose wording nobody here has ever read. The
    page's own words are still *quoted* when it offers any
    (`_idp_complaint`); they simply no longer decide.

    **Waiting for a state, never a duration.** Checking "is the form still
    there" after a fixed settle races the IdP's navigation. So this waits for
    the form to *go*, and only a timeout means it stayed.
    """
    del password  # never re-submitted, never logged: single attempt only
    if _looks_authenticated(page.url, target):
        return  # already through; nothing was rejected

    # With no family named, ask about every one we know. That is the honest
    # question at this point -- "is ANY credential form still up" -- and it
    # keeps the check usable by callers that did not do the submitting.
    selectors = ([idp.password_field] if idp
                 else [i.password_field for i in idps])
    try:
        page.wait_for_function(NO_OPERABLE_PASSWORD, arg=selectors,
                               timeout=timeout_ms)
        return
    except PlaywrightTimeout:
        pass
    except PlaywrightError:
        # The context was destroyed under us, which means the page navigated --
        # and navigating away IS the success signal. Not an error.
        return

    complaint = _idp_complaint(page)
    said = f" It says: {complaint!r}." if complaint else ""
    raise LoginError(
        f"The sign-in form at {host_of(page.url)} was still on screen "
        f"{timeout_ms // 1000}s after the credentials were submitted, so they "
        f"were not accepted.{said} Check {target.names.username_vars[0]} / "
        f"{target.names.password_vars[0]} in the secrets file. Nothing was "
        f"retried -- repeated attempts lock accounts."
    )


def log_in(page: Page, target: LoginTarget, username: str, password: str,
           approver: Approver | None = None,
           idps: tuple[IdP, ...] = IDPS,
           extra_recognisers: tuple[Recogniser, ...] = (),
           on_refuse: Callable[[LoginState], str] | None = None) -> None:
    """Perform a full SSO login, whatever the provider decides to ask for.

    **A recogniser loop, not a sequence.** The question at every step is *"is
    anything being asked, and can we answer it?"* -- never *"what comes
    third?"*. Plugin states dispatch through the same loop under the same
    once-each guard as the built-ins.

    `idps` is the set of families to recognise, `extra_recognisers` the plugin
    states that answer them. A second family arrives as a row plus recognisers
    passed here -- detection refuses unless exactly one row matches, so adding
    a row cannot silently re-route an existing host.
    """
    approver = approver or PushApprover()

    _log("Session expired or absent -- authenticating.")
    # Declare "no passkey" before the IdP can ask. This has to be installed
    # before any page script runs: a tenant whose default method is a passkey
    # leaves us on a progress bar forever otherwise, because headless Chromium
    # has no authenticator for `navigator.credentials.get()` to settle with.
    # Rejecting with `NotAllowedError` is exactly what a cancelled or
    # unavailable authenticator produces, and it is an honest statement of
    # capability -- only WebAuthn requests are answered this way.
    page.add_init_script(NO_PASSKEY)
    page.goto(target.sso_url, wait_until="domcontentloaded")
    quiesce(page)

    # A still-valid IdP session can carry us straight through without a form.
    if _looks_authenticated(page.url, target):
        _log("IdP session still valid; no credentials needed.")
        return

    # **Which family, decided once, from the page's own controls.** Read what
    # is there rather than trusting configuration. It refuses when two match
    # or none does.
    idp = detect_idp(page, idps=idps)
    _log(f"Identity provider: {idp.name}.")

    state = LoginState(page=page, target=target, username=username,
                       password=password, approver=approver, idp=idp,
                       on_refuse=on_refuse)
    _drive_login(state, extra_recognisers)

    if not state.answered_a_challenge:
        # A Duo page that never appeared can mean a remembered device -- or an
        # IdP that asked for no second factor at all. Report neither reading;
        # the loop knows what it saw and nothing about why.
        _log("No second factor presented (remembered device, or none required).")
    _log(f"Authenticated. Landed on {page.url}")


def _drive_login(state: LoginState,
                 extra_recognisers: tuple[Recogniser, ...] = ()) -> None:
    """Answer whatever the provider asks, until it stops asking.

    Returns only when authenticated; every other exit raises, so a caller can
    never mistake "we gave up" for "we are in".
    """
    recognisers = RECOGNISERS + tuple(extra_recognisers)
    while True:
        if _looks_authenticated(state.page.url, state.target):
            return

        found = _match(state, recognisers)
        if found is not None:
            if len(state.fired) >= MAX_LOGIN_STEPS:
                _refuse(state, "login-too-many-steps",
                        f"stopped after {MAX_LOGIN_STEPS} authentication "
                        f"steps without getting through")
            state.fired.append(found.name)
            _log(f"The provider is asking for {found.name}.")
            if found.challenges_human:
                state.answered_a_challenge = True
            found.handle(state)
            _settle(state.page)
            continue

        # Nothing we recognise is on screen. Either the flow is finishing (a
        # redirect chain, or a challenge in flight on someone's phone) or it has
        # stopped somewhere no recogniser understands. Both are answered by
        # watching -- for authentication OR for a state we do know.
        if _wait_for_progress(state, recognisers):
            continue
        _refuse(state, "login-incomplete",
                "stopped at a state no recogniser understands")


def _match(state: LoginState,
           recognisers: tuple[Recogniser, ...]) -> Recogniser | None:
    """The first recogniser that both matches and has not already fired.

    **Order is a tie-break, not a sequence.** Every detector asks about the page
    in front of it, so in a healthy flow at most one matches; the ordering only
    decides what happens if two ever did.
    """
    for recogniser in recognisers:
        # **Once each.** Every state here is a one-shot in every flow measured,
        # and this is what stops a provider re-presenting a challenge from
        # getting it answered twice -- each push rings a real phone.
        if recogniser.name in state.fired:
            continue
        try:
            if recogniser.detect(state):
                return recogniser
        except PlaywrightError:
            # A page mid-navigation destroys the evaluation context. That means
            # the question cannot be answered *right now*, not that the state is
            # absent; the caller polls again.
            continue
    return None


def _wait_for_progress(state: LoginState,
                       recognisers: tuple[Recogniser, ...]) -> bool:
    """Watch for authentication, or for a state we know how to answer.

    Returns whether something happened worth looping on.

    **Polls rather than sampling once.** After a second factor the browser is
    still walking a redirect chain, and a single check runs mid-chain and
    reports failure for a login that is merely still in flight.
    """
    # Long enough for a person to find their phone when one is waiting on them;
    # the shorter one is right for a redirect chain and absurd for a human.
    deadline_ms = (state.human_patience_ms if state.awaiting_human
                   else state.patience_ms)
    waited = 0
    while waited < deadline_ms:
        if _looks_authenticated(state.page.url, state.target):
            return True
        if _match(state, recognisers) is not None:
            return True
        try:
            state.page.wait_for_timeout(1_000)
        except PlaywrightError:
            return False
        waited += 1_000
    return False


def _refuse(state: LoginState, label: str, why: str) -> NoReturn:
    """Stop, and say what the provider was offering when we stopped."""
    page = state.page
    handled = ", ".join(state.fired) if state.fired else "nothing"
    # A pack may add what its provider was offering -- or raise a sharper
    # refusal first. Consulted before the generic report so the specific
    # diagnosis wins; a pack that cannot say more returns "".
    extra = ""
    if state.on_refuse is not None:
        try:
            extra = state.on_refuse(state) or ""
        except PlaywrightError:
            extra = ""
    # The page's own words, which need no selector and work for states this
    # code has never met.
    _report_page_text(page)
    snapshot = _snapshot(state, label)
    raise LoginError(
        f"Login {why} (url={page.url}). Answered so far: {handled}.{extra} "
        f"Nothing was retried. Snapshot: {snapshot}"
    )


# --- the states, and how each is answered -----------------------------------

#: Most states one sign-in may pass through before this stops and reports.
#:
#: **A bound, not a budget.** Every recogniser fires at most once, so a healthy
#: login cannot reach it; it exists so a provider that cycles stops rather than
#: spins.
MAX_LOGIN_STEPS = 12


@dataclass
class LoginState:
    """What the loop knows while driving one sign-in."""

    page: Page
    target: LoginTarget
    username: str
    password: str
    approver: Approver
    idp: IdP
    #: Which states have been answered, in order. Doubles as the "once each"
    #: guard and as what a refusal reports having done.
    fired: list[str] = field(default_factory=list)
    #: True once a challenge is in flight on a person's phone, which is the only
    #: reason to wait minutes rather than seconds.
    awaiting_human: bool = False
    #: Whether any second factor was answered at all -- so the run can say
    #: "none was presented" without claiming to know why.
    answered_a_challenge: bool = False
    #: How long to watch for something to happen when nothing is on screen we
    #: recognise. **Named rather than buried**: these were two magic numbers in
    #: the old sequence, and one of them is the difference between "a redirect
    #: chain is still walking" and "a person has to find their phone".
    patience_ms: int = 30_000
    human_patience_ms: int = 150_000
    #: Pack-supplied refusal detail. A pack that knows what its provider offers
    #: (a rejected username is not a bad password) reports it here -- or raises
    #: a sharper refusal first. Runs before the generic report so the specific
    #: diagnosis wins. `None` means the generic refusal stands alone.
    on_refuse: Callable[[LoginState], str] | None = None


@dataclass(frozen=True)
class Recogniser:
    """One page state, and what to do about it.

    **Named for what the PROVIDER is asking**, not for a step number. That is
    the whole point of the design: `name` appears in the log and in refusals,
    and reads correctly whichever position the state turns up in.

    This is also the plugin contract: a bespoke system contributes `Recogniser`
    rows (plus an `IdP` row for `detect_idp`), and the loop dispatches them
    with the same once-each guard as the built-ins.
    """

    name: str
    detect: Callable[[LoginState], bool]
    handle: Callable[[LoginState], None]
    #: Whether answering this asks something of a person. Drives both the long
    #: wait and the "no second factor presented" line.
    challenges_human: bool = False


def _operable(state: LoginState, *selectors: str) -> bool:
    """Whether any of these is a control a person could actually use.

    **Never `is_visible()`**, which ignores opacity: a parked, invisible box
    is called visible by Playwright while `fill` succeeds on it. Typing a
    password into a box nobody can see raises nothing at all.

    This is what makes the detectors trustworthy enough to double as the wait.
    The old code waited for an operable password box and then typed; here the
    handler is only reachable when the box is *already* operable, so the
    guarantee is structural rather than sequential.
    """
    return bool(state.page.evaluate(OPERABLE_PASSWORD, list(selectors)))


def _present(state: LoginState, selector: str) -> bool:
    """Whether the selector matches anything at all -- presence, not visibility."""
    try:
        return state.page.locator(selector).count() > 0
    except PlaywrightError:
        return False


def _sees_duo(state: LoginState) -> bool:
    return on_duo_page(state.page)


def _answer_duo(state: LoginState) -> None:
    _log(f"Using '{state.approver.name}' approval.")
    # Snapshot the Duo page while we are actually on it. Its DOM is otherwise
    # unobservable during development (reaching it needs real credentials), and
    # this is the evidence any future selector repair depends on.
    _log(f"Duo page captured: {_snapshot(state, 'duo-live')}")
    complete_duo(state.page, state.approver)


def _sees_single_screen_form(state: LoginState) -> bool:
    """Single-screen form: all fields at once, answered in one go.

    **`two_screen` is what keeps this from matching a two-screen password.**
    A single-screen form holds an operable password box too, so without the
    gate two states would claim the same page -- and the loop would be relying
    on its own ordering to resolve something that should not be ambiguous at
    all.
    """
    return (not state.idp.two_screen
            and _operable(state, state.idp.password_field))


def _submit_single_screen(page: Page, username: str, password: str,
                          idp: IdP) -> None:
    """Both fields and one click -- the single-screen shape, proven live."""
    page.fill(idp.username_field, username)
    page.fill(idp.password_field, password)
    page.click(idp.submit)
    page.wait_for_load_state("domcontentloaded")


def _answer_single_screen_form(state: LoginState) -> None:
    _submit_single_screen(state.page, state.username, state.password,
                          state.idp)
    _settle(state.page)
    _check_for_credential_rejection(
        state.page, state.target, state.username, state.password,
        idp=state.idp)


#: Every page state the core can answer.
#:
#: **A set, not a script.** Adding a screen is a row here (or a plugin row
#: passed via `extra_recognisers`), not a re-plumbing of a sequence.
RECOGNISERS: tuple[Recogniser, ...] = (
    Recogniser("a Duo challenge", _sees_duo, _answer_duo,
               challenges_human=True),
    Recogniser("a sign-in form", _sees_single_screen_form,
               _answer_single_screen_form),
)


#: Tell the IdP, truthfully, that there is no passkey here.
#:
#: **Without this the login hangs rather than failing.** A tenant whose default
#: method is a passkey leaves headless Chromium -- which has no authenticator
#: at all -- on a progress bar forever: `navigator.credentials.get()` never
#: settles, and a pending promise is a state no real browser rests in.
#:
#: Rejecting with `NotAllowedError` is exactly what a cancelled or unavailable
#: authenticator produces, and it is **an honest statement of capability**.
#: Only WebAuthn requests are answered this way; anything else passes through.
NO_PASSKEY = """
if (navigator.credentials && navigator.credentials.get) {
  const real = navigator.credentials.get.bind(navigator.credentials);
  navigator.credentials.get = (opts) => (opts && opts.publicKey)
    ? Promise.reject(new DOMException(
        'No authenticator is available to this client.', 'NotAllowedError'))
    : real(opts);
}
"""


def _report_page_text(page: Page) -> None:
    """Print the page's own visible words.

    **Needs no selector, and so works for states this code has never met** --
    which is why it is also what a refusal prints. Split out so that a state
    we do not recognise reports itself without being given any approver's box,
    which would tell the reader to approve something nobody asked for.
    """
    try:
        text = page.inner_text("body") or ""
    except PlaywrightError:
        return
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return
    _log("The identity provider is asking for something this tool cannot "
         "answer by itself. It says:")
    for line in lines[:10]:
        _log(f"    {line[:100]}")


def ensure_logged_in(page: Page, target: LoginTarget,
                     username: str, password: str,
                     approver: Approver | None = None,
                     idps: tuple[IdP, ...] = IDPS,
                     extra_recognisers: tuple[Recogniser, ...] = (),
                     on_refuse: Callable[[LoginState], str] | None = None,
                     ) -> bool:
    """Guarantee an authenticated session. Returns True if a login was performed.

    Every task entry point should call this first. When the session is warm this
    costs one page load and involves no human at all.
    """
    if is_logged_in(page, target):
        _log("Existing session is still good.")
        return False
    log_in(page, target, username, password, approver, idps=idps,
           extra_recognisers=extra_recognisers, on_refuse=on_refuse)
    return True
