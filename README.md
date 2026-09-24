# multipass

Reusable browser-login building blocks, spun out of
[canvasser](https://github.com/doctorjei/canvasser). Import name and
distribution are both `multipass`. GPL-3.0-or-later.

Ships four modules: **credential resolution** (`multipass.credentials`),
**persistent browser contexts** with 700/600 debug snapshots (`multipass.browser`),
a **branding skeleton** (`multipass.config` — state layout plus every brandable
string in one frozen object), and the **recogniser-loop auth engine**
(`multipass.auth`: `LoginState` dispatch, one IdP row, structural rejection
check, allowlist liveness) with Duo answered through the `duo-pass`
dependency. Factor plugins beyond Duo arrive through `extra_recognisers`.

```python
from pathlib import Path
from multipass import CredentialNames, resolve_credentials

NAMES = CredentialNames(
    username_vars=("CONCURRER_USERNAME",),
    password_vars=("CONCURRER_PASSWORD",),
    program="concurrer",
)

user, pw = resolve_credentials(
    names=NAMES,
    default_file=Path.home() / ".local" / "state" / "concurrer" / "secrets.env",
)
```

## Branding

A library must not hardcode its first host's variable names — and it must not
hold them as setup either. Every variable, flag example, and program name the
package can utter arrives per call, in one frozen `CredentialNames` the host
constructs and passes in (`resolve_credentials(names=...)`,
`LoginTarget(names=...)`). There is no `configure()`, no active branding, and
no default to inherit: a default here would be the thing every host silently
inherits. The `MULTIPASS_*` object exists only so the shape has something to
show, not something to run under. State paths work the same way:
`resolve_state_dir(config)` takes its `AuthConfig` explicitly, and the
browser's snapshot directory, session file, and profile dir are required
arguments wherever they are used.
