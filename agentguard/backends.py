"""Model-backend adapters for the guarded harness.

AgentGuard is model-agnostic: the policy engine and audit log don't care which
model powers the agent. A backend is anything that turns a prompt into text.

Verified IBM Bob integration surface (see docs/bob-integration.md):
  * Bob Shell CLI in non-interactive mode, authenticated with an API key
    (``BOBSHELL_API_KEY``) created at bob.ibm.com. There is NO documented
    public REST API for Bob inference — do not invent one.

Backends raise :class:`BackendUnavailable` with a plain-English explanation
when their prerequisites are missing. They never fabricate output.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from abc import ABC, abstractmethod


class BackendUnavailable(RuntimeError):
    """The backend cannot run here (missing binary, key, etc.)."""


class BackendError(RuntimeError):
    """The backend ran but failed."""


class ModelBackend(ABC):
    """Anything that turns a prompt into model text."""

    name: str = "base"

    @abstractmethod
    def generate(self, prompt: str, timeout: int = 180) -> str:
        """Return the model's text response. Raises BackendUnavailable/Error."""


class BobShellBackend(ModelBackend):
    """Drive IBM Bob headlessly through the Bob Shell CLI.

    Prerequisites (done once by the human operator):
      1. Install Bob Shell: https://bob.ibm.com/docs/shell/getting-started/install-and-setup
      2. Sign up / sign in at https://bob.ibm.com and create an API key
         (Inference scope is enough): https://bob.ibm.com/docs/ide/account/api-keys
      3. ``export BOBSHELL_API_KEY="<key>"``

    The exact CLI flags vary by Bob Shell version; override with
    ``BOBSHELL_CMD`` as a template containing ``{prompt}``, e.g.::
        BOBSHELL_CMD='bob --auth-method api-key -p "{prompt}"'
    Run ``bob --help`` on your machine to confirm the flags.
    """

    name = "bob-shell"
    DEFAULT_CMD = 'bob --auth-method api-key -p "{prompt}"'

    def __init__(self, api_key: str | None = None, cmd_template: str | None = None):
        self.api_key = api_key or os.environ.get("BOBSHELL_API_KEY", "")
        self.cmd_template = cmd_template or os.environ.get(
            "BOBSHELL_CMD", self.DEFAULT_CMD
        )

    def check(self) -> None:
        if shutil.which("bob") is None:
            raise BackendUnavailable(
                "the `bob` CLI is not on PATH. Install Bob Shell from "
                "https://bob.ibm.com/docs/shell/getting-started/install-and-setup"
            )
        if not self.api_key:
            raise BackendUnavailable(
                "BOBSHELL_API_KEY is not set. Create an API key at "
                "https://bob.ibm.com/docs/ide/account/api-keys and export it."
            )

    def generate(self, prompt: str, timeout: int = 180) -> str:
        self.check()
        cmd = self.cmd_template.replace("{prompt}", prompt)
        argv = shlex.split(cmd)
        env = dict(os.environ, BOBSHELL_API_KEY=self.api_key)
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout, env=env
            )
        except subprocess.TimeoutExpired as exc:
            raise BackendError(f"bob timed out after {timeout}s") from exc
        if proc.returncode != 0:
            raise BackendError(
                f"bob exited {proc.returncode}: {(proc.stderr or proc.stdout).strip()[:500]}"
            )
        return proc.stdout.strip()
