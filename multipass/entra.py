"""Microsoft Entra ID as an IdP pack for the multipass recogniser loop.

Ported from canvasser's proven implementation (measured live at UCF,
2026-09-11 — the first non-Shibboleth IdP, on someone else's account). The
port is structural, not behavioral: selectors, cross-checks, refusals, and
comments move verbatim except where the host boundary moved them:

- `state.config.*` becomes `state.*` (`username`, `password`) or a factory
  argument (`passwordless`). The pack never sees the host's config object.
- Snapshots go through `_snapshot(state, label)` so they land in the host's
  directory under its sensitivity gate, never a default.
- The number-match report goes through `show_number`, supplied by the host
  (canvasser draws its `code_box` frame); the page's own text still prints
  through `_report_page_text`, which needs no selector.
- The OTP code is read through `credentials._read_from_tty` -- same package,
  same terminal discipline, still never stored.

Use:

    pack = entra_pack(passwordless=False, show_number=host_framer)
    log_in(page, target, user, pw, approver,
           idps=IDPS + (pack.idp,),
           extra_recognisers=pack.recognisers,
           on_refuse=pack.on_refuse)

Provenance notes, kept because they constrain what may change:

- Markers, tile ids, and the `data-value`/`data-test-cred-id` distinction are
  MEASURED (2026-09-11). The number-match selectors are an UNMEASURED GUESS --
  provoking a number match rings a real person's phone -- and are treated as
  one throughout: the box is drawn whether or not a number was found.
- No digit-scan fallback for the number (unlike Duo): Duo's codes are three
  digits and Entra's are two, and a bare two-digit line is far likelier to
  match something that is not the code. A bogus number is worse than none.
- The OTP seed is never stored anywhere: automating the code from a TOTP seed
  would put both factors in one file.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass
from playwright.sync_api import (Error as PlaywrightError, Page,
                                 TimeoutError as PlaywrightTimeout)

from .auth import (IdP, LoginError, LoginState, Recogniser,
                   _check_for_credential_rejection, _idp_complaint, _log,
                   _operable, _present, _refuse, _report_page_text, _settle,
                   _snapshot, OPERABLE_PASSWORD)
from .credentials import _read_from_tty

__all__ = [
    "ENTRA",
    "EntraPack",
    "ShowNumber",
    "entra_pack",
]


#: UCF (measured 2026-09-11). Microsoft Entra ID. **`#idSIButton9` is
#: deliberately the submit for both screens** -- Microsoft reuses that id,
#: labelling it "Next" on the username screen and "Sign in" on the password
#: screen, so one selector genuinely serves both steps.
ENTRA = IdP(
    name="Microsoft Entra ID",
    username_field="input[name='loginfmt']",
    password_field="input[name='passwd']",
    submit="#idSIButton9",
    two_screen=True,
    # The picker link and the credential tiles are what a remembered
    # account shows instead of a username box.
    markers=("input[name='loginfmt']", "input[name='passwd']",
             "#idA_PWD_SwitchToCredPicker",
             "[role=button][data-test-cred-id]"),
)

#: "Sign in another way" -- Entra's credential picker. Measured, not guessed.
ENTRA_CRED_PICKER = "#idA_PWD_SwitchToCredPicker"

#: The password tile in that picker. `data-test-cred-id` is Entra's credential
#: *type*, and `1` is password; the tile is a `role=button` div, not a link.
#: **The label is cross-checked before it is clicked** -- "the id still exists"
#: and "the id still means what it meant" are different claims, and the cost of
#: clicking the wrong tile here is a push notification at a real person's phone.
ENTRA_PASSWORD_TILE = '[role=button][data-test-cred-id="1"]'
ENTRA_PASSWORD_WORDS = ("password",)

#: The same picker's **passwordless** tile: the authenticator app as the
#: PRIMARY credential, not as a second factor. Measured 2026-09-11 alongside
#: the password tile (`7` is the passkey, `1` the password, `2` this).
#:
#: **This is a different thing from `ENTRA_PUSH`**, which appears later and
#: only after a password. Same app, same tap, different role in the flow --
#: and choosing it means there is no password to store at all.
ENTRA_APP_TILE = '[role=button][data-test-cred-id="2"]'
ENTRA_APP_WORDS = ("authenticator", "approve")

#: Entra's passwordless challenge. Measured at UCF 2026-09-11: the flow leaves
#: `login.microsoftonline.com` for `login.microsoft.com/<tenant>/fido/get`, and
#: the page's own `$Config` carries `sFidoChallenge`. **Both are checked** --
#: the URL because it is settled and cheap, the config key because a route can
#: be renamed while the capability cannot.
FIDO_MARKERS = """
() => ({
  url: /\\/fido\\//.test(location.pathname),
  challenge: !!(window.$Config && window.$Config.sFidoChallenge),
})
"""


def _entra_stall_reason(state: LoginState) -> str:
    """Why no password box appeared -- in terms the reader can act on.

    Two causes need opposite fixes, and telling them apart is the whole point:

    * **Still on the username screen** -- the username was refused. Go and fix
      the credential setting.
    * **Moved on to something that is not a password** -- the username was
      *accepted*, and the account is being asked for a different factor. The
      credential setting is correct and editing it makes things worse.

    A passkey is the case that matters, and it is not a selector problem: a
    FIDO2 credential lives in hardware, so there is nothing this tool could
    type even in principle. Saying so plainly beats a message that implies a
    fix exists.
    """
    page = state.page
    username_var = state.target.names.username_vars[0]
    try:
        if page.evaluate(OPERABLE_PASSWORD, [state.idp.username_field]):
            return (f"The sign-in form is still asking for a username, so it "
                    f"was not accepted -- check {username_var} in the secrets "
                    f"file, and whether this provider wants a full address "
                    f"rather than a bare name.")
    except PlaywrightError:
        pass

    try:
        fido = page.evaluate(FIDO_MARKERS)
    except PlaywrightError:
        fido = {}
    if fido.get("url") or fido.get("challenge"):
        return (
            "The username WAS accepted -- this provider is asking for a "
            "passkey or security key (FIDO2: face, fingerprint, PIN or "
            "hardware key) instead of a password. That is an account or tenant "
            "policy, not a configuration error here, and it cannot be "
            "satisfied by a stored password: the credential lives in hardware. "
            f"Leave {username_var} alone. Either enable password sign-in for "
            "this account, or choose another sign-in method if the provider "
            "offers one.")

    offered = _entra_factor_offered(page)
    if offered:
        # Measured 2026-09-11: a remembered account is taken straight to
        # "Verify your identity", whose tiles are verification METHODS and
        # include no password at all. Naming the flag is the actionable part.
        return (
            f"The username was accepted and this provider went straight to "
            f"choosing a verification method ({', '.join(offered)}) -- it is "
            f"not offering a password at all. Use --passwordless to sign in "
            f"with the authenticator app instead.")

    return ("The username appears to have been accepted, but the next screen "
            "was not a password box -- this provider may be asking for another "
            f"factor. Check the snapshot before changing {username_var}.")


def _choose_password_method(page: Page) -> bool:
    """Open the picker and select the password. Kept as its own name because
    that is what the password path asks for; the work is shared below."""
    return _choose_primary_method(page, ENTRA_PASSWORD_TILE,
                                  ENTRA_PASSWORD_WORDS)


def _choose_primary_method(page: Page, tile_selector: str,
                           expect_words: tuple[str, ...]) -> bool:
    """Open Entra's credential picker and select one PRIMARY credential.

    Returns whether it got there. **Selects the asked-for tile and nothing
    else**: the other tiles include "Approve a request on my Microsoft
    Authenticator app", and clicking that sends a notification to a real
    person's phone that nobody is waiting for.
    """
    picker = page.locator(ENTRA_CRED_PICKER)
    try:
        # **Wait for it rather than sampling once.** The link appears only
        # after the passkey attempt has been declined and the page has
        # re-rendered, so an immediate `count()` races that and reports "no
        # picker offered" for a page that is about to offer one. A state, not
        # a duration -- the rule this project keeps re-earning.
        picker.first.wait_for(state="visible", timeout=20_000)
        picker.first.click()
    except (PlaywrightTimeout, PlaywrightError):
        return False

    tile = page.locator(tile_selector)
    try:
        tile.wait_for(state="visible", timeout=15_000)
    except (PlaywrightTimeout, PlaywrightError):
        return False

    # More than one match means the credential id no longer identifies one
    # control, so refuse rather than pick -- the ambiguous Save button rule.
    if tile.count() != 1:
        return False

    # The id says *which* credential type; the label says what the user is
    # being offered. Both must agree before we click something that could be
    # a second factor rather than a password.
    label = (tile.first.get_attribute("aria-label") or "").lower()
    if label and not any(w in label for w in expect_words):
        _log(f"Refusing the credential tile: its id and its label {label!r} "
             f"disagree about what it is.")
        return False

    tile.first.click()
    return True


def _raise_entra_stall(state: LoginState) -> None:
    """Report why no password box appeared, and stop."""
    page = state.page
    complaint = _idp_complaint(page)
    snapshot = _snapshot(state, "login-username-stuck")
    said = f" It says: {complaint!r}." if complaint else ""
    raise LoginError(
        f"{state.idp.name} never presented a password box after the username "
        f"was submitted (url={page.url}).{said} "
        f"{_entra_stall_reason(state)} "
        f"Nothing was retried. Snapshot: {snapshot}"
    )


def _sees_username_box(state: LoginState) -> bool:
    return state.idp.two_screen and _operable(state, state.idp.username_field)


def _answer_username_box(state: LoginState) -> None:
    state.page.fill(state.idp.username_field, state.username)
    state.page.click(state.idp.submit)
    state.page.wait_for_load_state("domcontentloaded")


def _answer_password_box(state: LoginState) -> None:
    state.page.fill(state.idp.password_field, state.password)
    state.page.click(state.idp.submit)
    state.page.wait_for_load_state("domcontentloaded")
    _settle(state.page)
    # **Fail fast on a rejection, next to the submission that could be
    # rejected.** Repeatedly submitting a wrong password is how accounts lock.
    _check_for_credential_rejection(
        state.page, state.target, state.username, state.password,
        idp=state.idp)


def _sees_credential_picker(state: LoginState) -> bool:
    """Entra's PRIMARY picker -- which credential to sign in with.

    **Told apart from the verification picker by the attributes that actually
    differ**, both measured 2026-09-11: primary tiles are keyed by
    `data-test-cred-id`, verification tiles by `data-value` (an
    `authMethodId`). Requiring no verification tiles here, and no primary
    picker there, makes the two mutually exclusive rather than order-dependent
    -- so neither can be mistaken for the other on a page carrying both.
    """
    return (_present(state, ENTRA_CRED_PICKER)
            and not _entra_factor_offered(state.page))


def _sees_method_picker(state: LoginState) -> bool:
    """Entra's verification tiles -- which factor to answer with."""
    return (not _present(state, ENTRA_CRED_PICKER)
            and bool(_entra_factor_offered(state.page)))


def _looks_like_a_rejected_username(state: LoginState) -> bool:
    """We typed a username, waited, and the box is *still* asking for one.

    **Deliberately NOT a recogniser**, and the reason is worth keeping: it
    would fire on a perfectly healthy login. Entra's view switch is client-side
    and takes the better part of a second, during which the username box is
    still operable and the password box is not -- so a recogniser saying "the
    username box is still there" matches the ordinary flow mid-switch and
    refuses a sign-in that was about to work.

    The conclusion is only sound *after* the wait has been spent, which is
    exactly where the refusal stands. Recognisers answer what is on screen now;
    this answers what is still on screen after nothing else happened.
    """
    if not state.idp.two_screen or "a username" not in state.fired:
        return False
    try:
        return _operable(state, state.idp.username_field)
    except PlaywrightError:
        return False


def _entra_refusal(state: LoginState) -> str:
    """Pack refusal detail: a rejected username, and what is on offer.

    Consulted by the core refusal before the generic report, so the specific
    diagnosis wins. A rejected USERNAME is reported as itself, not as a bad
    password -- the two need opposite fixes and send the reader to different
    lines of the secrets file.
    """
    if _looks_like_a_rejected_username(state):
        _raise_entra_stall(state)
    offered = _entra_factor_offered(state.page)
    if offered:
        return (f" The provider is offering: {', '.join(offered)} -- none of "
                f"which this build can answer.")
    return ""


def _sees_code_box(state: LoginState) -> bool:
    return _present(state, ENTRA_OTP_FIELD)


def _answer_code_box(state: LoginState) -> None:
    state.awaiting_human = True
    _complete_entra_otp(state)


#: Entra's second-factor tiles. `data-value` carries the `authMethodId` straight
#: out of `$Config.arrUserProofs`, so this is the method's own name rather than
#: the English words next to it -- measured at UCF 2026-09-11.
ENTRA_FACTOR_TILES = '[role=button][data-value]'

#: Push with number matching: the page displays a number, the human taps it in
#: the Authenticator app, and the page polls (`oPerAuthPollingInterval` is 1s)
#: until it is approved. **Duo's shape exactly**, which is why the same seam
#: serves both.
#:
#: **The other two registered methods are deliberately not driven.** `FidoKey`
#: needs hardware this process does not have. `PhoneAppOTP` *could* be
#: automated -- and must not be: storing the TOTP seed would put both factors
#: in one file, which is the one thing this design has refused since it was
#: written.
ENTRA_PUSH = "PhoneAppNotification"


#: The Authenticator's rotating code, typed by a human. Measured 2026-09-11.
#: `maxlength=6`, `inputmode=numeric`, labelled "Code"; the submit reads
#: "Verify".
ENTRA_OTP = "PhoneAppOTP"
ENTRA_OTP_FIELD = "input[name='otc']"
ENTRA_OTP_SUBMIT = "#idSubmit_SAOTCC_Continue"

#: Which factor name each `--factor` maps to. **The flag already existed for
#: Duo**, and reusing it keeps one vocabulary for "how do you want to answer the
#: second factor" rather than inventing a parallel one per IdP.
ENTRA_FACTOR_FOR = {"push": ENTRA_PUSH, "passcode": ENTRA_OTP}


def _entra_factor_offered(page: Page) -> list[str]:
    """Which second factors this IdP is offering, by `authMethodId`."""
    try:
        return page.eval_on_selector_all(
            ENTRA_FACTOR_TILES,
            "els => els.map(e => e.getAttribute('data-value')).filter(Boolean)")
    except PlaywrightError:
        return []


def _choose_entra_factor(page: Page, prefer: str = "push") -> str | None:
    """Pick a second factor. Returns the `authMethodId` chosen, or None.

    Chosen **by `authMethodId`, never by the words on the tile** -- the same
    value-not-label rule, arriving at the IdP.

    Falls back to the other supported method when the preferred one is not
    registered, because refusing a login over a flag default helps nobody --
    but it says which it took, since the two need different things from the
    human (a phone tap versus a typed code).
    """
    offered = _entra_factor_offered(page)
    if not offered:
        return None

    wanted = ENTRA_FACTOR_FOR.get(prefer, ENTRA_PUSH)
    order = [wanted] + [m for m in (ENTRA_PUSH, ENTRA_OTP) if m != wanted]
    for method in order:
        if method not in offered:
            continue
        tile = page.locator(f'[role=button][data-value="{method}"]')
        if tile.count() != 1:
            continue  # ambiguous: refuse rather than choose
        if method != wanted:
            _log(f"{wanted} is not registered on this account; using {method}.")
        tile.first.click()
        return method

    # `FidoKey` lands here, and correctly: it needs hardware this process does
    # not have, so there is nothing to fall back to.
    _log(f"This account offers {', '.join(offered)}; none is a factor this "
         f"tool can answer.")
    return None


def _complete_entra_otp(state: LoginState) -> None:
    """Prompt for the Authenticator's code and submit it.

    **Nothing is stored.** The code is read from the terminal, typed into the
    form, and forgotten -- so this stays genuinely two-factor.

    Read through `/dev/tty` rather than stdin, like every other interactive
    prompt here: a piped or `sshpass`-driven run has a terminal even when stdin
    is not one.
    """
    page = state.page
    try:
        page.wait_for_selector(ENTRA_OTP_FIELD, timeout=30_000)
    except PlaywrightTimeout as exc:
        snapshot = _snapshot(state, "entra-otc-missing")
        raise LoginError(
            f"Chose the Authenticator code method, but no code box appeared "
            f"(url={page.url}). Snapshot: {snapshot}") from exc

    code = _read_from_tty(
        "  Enter the 6-digit code from Microsoft Authenticator: ").strip()
    if not code:
        raise LoginError("No code entered; nothing was submitted.")

    page.fill(ENTRA_OTP_FIELD, code)
    submit = page.locator(ENTRA_OTP_SUBMIT)
    if submit.count() == 1:
        submit.first.click()
    else:
        # The form submits on Enter here. Safe in a way it is NOT on a form
        # holding a half-typed row -- this page holds one field and one action.
        page.press(ENTRA_OTP_FIELD, "Enter")
    page.wait_for_load_state("domcontentloaded")


#: Where Entra's number-match code might be. **UNMEASURED, and treated as a
#: guess throughout.** Nobody here has read this markup: the one live UCF login
#: rendered the number through the text dump below, and provoking another means
#: ringing a real person's phone, which is not a thing to do for a selector.
#:
#: So this is candidates-and-shrug. A hit renders the number in the box; a miss
#: costs nothing, because the box is drawn either way and the page's own text
#: still follows it. What must NOT happen is a bogus number -- telling someone
#: to tap `1` scraped from unrelated markup is worse than telling them nothing.
#:
#: **No digit-scan fallback here, deliberately**: a bare two-digit line is far
#: likelier to match something that is not the code.
ENTRA_NUMBER_SELECTORS = (
    "#idRichContext_DisplaySign",
    "[data-bind*='displaySign']",
    "[class*='displaySign']",
)


def _read_entra_number(page: Page) -> str | None:
    """The number Entra is displaying for the human to match, if we can find it.

    Absence is normal and never an error -- see `ENTRA_NUMBER_SELECTORS`.
    """
    for selector in ENTRA_NUMBER_SELECTORS:
        try:
            text = page.locator(selector).first.inner_text(timeout=1_000)
        except Exception:                                       # noqa: BLE001
            continue
        digits = "".join(ch for ch in text if ch.isdigit())
        # A number match is short. Anything longer is some other element that
        # happened to match, and passing it on would be the bogus-code failure.
        if digits and len(digits) <= 3:
            return digits
    return None


#: How the number-match code reaches the human. The box is the unmissable
#: half; the page's own text (printed after, by the caller) is the half that
#: needs no selector. A host with its own display layer supplies its own.
ShowNumber = Callable[[str | None], None]


def _default_show_number(number: str | None) -> None:
    """A framed box on stderr. A prompt to a human, not captured output."""
    body = (f"Tap {number} in Microsoft Authenticator." if number else
            "Approve in Microsoft Authenticator (no number shown).")
    width = len(body) + 4
    bar = "+" + "-" * (width - 2) + "+"
    print(f"\n  {bar}\n  | {body} |\n  {bar}\n", file=sys.stderr, flush=True)


def _report_pending_factor(page: Page, show_number: ShowNumber) -> None:
    """Print what the IdP is showing, when it is showing something we cannot drive.

    **The screen is the only place a number-match code exists**, and it is
    rendered in a headless browser nobody can see -- so without this the run is
    unapprovable even with the person sitting right there.

    **Two halves, and only one of them depends on a selector.** The box is drawn
    *whether or not* the number was found, so the prompt itself is unmissable
    even when the guessed selector misses; that half is guaranteed. The page's
    **own visible text** still follows, needing no guess and working for factors
    this code has never met.
    """
    show_number(_read_entra_number(page))
    _report_page_text(page)


@dataclass(frozen=True)
class EntraPack:
    """Everything a host needs to drive Entra, in one value.

    Built by `entra_pack`, which is also where the host-only choices live
    (`passwordless`, the number display). The host passes the three fields to
    `log_in` -- `idps`, `extra_recognisers`, `on_refuse` -- so a row can never
    arrive without the recognisers that answer it.
    """

    idp: IdP
    recognisers: tuple[Recogniser, ...]
    on_refuse: Callable[[LoginState], str] | None


def entra_pack(*, passwordless: bool = False,
               show_number: ShowNumber | None = None) -> EntraPack:
    """Build the Entra pack for one host's choices.

    `passwordless` makes the authenticator app the primary credential: no
    password box is ever answered, so a stored password cannot silently demote
    the app to a second factor. `show_number` draws the number-match box (the
    default frames it on stderr); the page's own text always follows.
    """
    show = show_number or _default_show_number

    def _sees_password_box(state: LoginState) -> bool:
        # **Under passwordless a password box is not a state we answer.** The
        # app is the credential; typing a stored password would silently demote
        # it to a second factor, which is the opposite of what was asked for.
        if passwordless:
            return False
        # A password ON ITS OWN is the two-screen shape. A single-screen form
        # is answered whole, by the core recogniser.
        if not state.idp.two_screen:
            return False
        return _operable(state, state.idp.password_field)

    def _answer_credential_picker(state: LoginState) -> None:
        if passwordless:
            # **The app IS the credential here**, so there is no password step
            # at all: nothing is typed afterwards and none is stored.
            if not _choose_primary_method(state.page, ENTRA_APP_TILE,
                                          ENTRA_APP_WORDS):
                snapshot = _snapshot(state, "login-no-passwordless")
                raise LoginError(
                    f"Passwordless sign-in was asked for, but this account was "
                    f"not offered an authenticator app as a primary credential "
                    f"(url={state.page.url}). Drop passwordless to use the "
                    f"stored password instead. Snapshot: {snapshot}")
            state.awaiting_human = True
            _log("Passwordless sign-in: approve the request in Microsoft "
                 "Authenticator -- match the number shown below.")
            _settle(state.page)
            _report_pending_factor(state.page, show)
            return

        # **"No password box" is not the end of the road.** A tenant whose
        # default method is a passkey shows that first; the password lives
        # behind "Sign in another way".
        if not _choose_password_method(state.page):
            _raise_entra_stall(state)

    def _answer_method_picker(state: LoginState) -> None:
        chosen = _choose_entra_factor(state.page, state.approver.name)
        if chosen is None:
            # `FidoKey` alone lands here, and correctly: it needs hardware this
            # process does not have, so there is nothing to fall back to.
            _refuse(state, "login-no-answerable-factor",
                    "reached a verification step it cannot answer")
        state.awaiting_human = True
        _settle(state.page)
        if chosen == ENTRA_OTP:
            # The code box is the next state, recognised on its own.
            _log("Second factor: Microsoft Authenticator code.")
            return
        _log("Second factor: Microsoft Authenticator push. Approve it on your "
             "phone -- match the number shown below.")
        _report_pending_factor(state.page, show)

    recognisers = (
        Recogniser("a username", _sees_username_box, _answer_username_box),
        Recogniser("a password", _sees_password_box, _answer_password_box),
        Recogniser("an authenticator code", _sees_code_box, _answer_code_box,
                   challenges_human=True),
        Recogniser("which credential to use", _sees_credential_picker,
                   _answer_credential_picker),
        Recogniser("which verification method to use", _sees_method_picker,
                   _answer_method_picker, challenges_human=True),
    )
    return EntraPack(idp=ENTRA, recognisers=recognisers,
                     on_refuse=_entra_refusal)
