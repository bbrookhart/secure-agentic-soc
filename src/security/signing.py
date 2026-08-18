"""Signing audit records, and anchoring the chain outside this host.

Be precise about what this buys, because it is easy to overclaim.

The hash chain proves *internal consistency*: edit one event and every later
link breaks. It proves nothing about origin, and an attacker who can run this
code can recompute the whole chain and leave it perfectly consistent.

Signing adds two things the chain cannot:

* **Non-repudiation to a third party (NIST 800-53 AU-10).** An auditor holding
  only the public key can verify that records came from this deployment's
  signing key. Verification no longer requires the power to forge, which is the
  property that makes an audit log worth showing to someone who does not trust
  you.
* **Anchoring, when combined with forwarding.** Periodically the current chain
  head -- sequence number and hash -- is signed and shipped to the external
  sink. A later local rewrite produces a log whose head disagrees with anchors
  the attacker cannot retract, because they already left the host. Divergence is
  the detection.

What it does **not** buy: protection from an attacker who holds the signing key.
With the key on local disk, code execution still means forgery. The honest
mitigation is to keep the key somewhere the application can use but not read --
a KMS or HSM -- so that signing is an operation rather than a secret. That is a
deployment decision, and :class:`AuditSigner` is the seam for it: implement the
protocol against a KMS and nothing else changes.

Key handling here: an Ed25519 key is generated on first use at the configured
path with owner-only permissions, and its generation is itself an audited event
with the public-key fingerprint recorded. A silently created key nobody knows
about is not key management, so the fingerprint is surfaced by ``make audit``
and in the evidence bundle.
"""

from __future__ import annotations

import base64
import hashlib
import os
import stat
from pathlib import Path
from typing import Any, Protocol

_KEY_COMMENT = (
    "# Agentic SOC audit signing key (Ed25519).\n"
    "# Anyone holding this file can forge audit records. In production, use a\n"
    "# KMS or HSM instead so the application can sign without reading the key.\n"
)


class AuditSigner(Protocol):
    """Anything that can sign an audit record.

    The seam for KMS/HSM backends: implement this and the audit logger is
    unchanged.
    """

    @property
    def key_id(self) -> str: ...

    def sign(self, data: bytes) -> str: ...

    def public_key_pem(self) -> str: ...


class NullSigner:
    """No signing. Records carry an empty signature."""

    @property
    def key_id(self) -> str:
        return ""

    def sign(self, data: bytes) -> str:
        return ""

    def public_key_pem(self) -> str:
        return ""


class Ed25519Signer:
    """Ed25519 signing with a key on local disk.

    Generates the key on first use. Ed25519 is chosen over RSA for size and
    speed -- signing is on the path of every audit write, and a 64-byte
    signature keeps the log readable.
    """

    def __init__(self, key_path: Path, *, create_if_missing: bool = True) -> None:
        self.key_path = Path(key_path)
        self.created = False
        self._private_key = self._load_or_create(create_if_missing)

    def _load_or_create(self, create_if_missing: bool) -> Any:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        if self.key_path.exists():
            data = self.key_path.read_bytes()
            key = serialization.load_pem_private_key(data, password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise TypeError(f"{self.key_path} is not an Ed25519 private key")
            self._warn_if_readable_by_others()
            return key

        if not create_if_missing:
            raise FileNotFoundError(f"audit signing key not found: {self.key_path}")

        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        # Create with owner-only permissions from the outset rather than
        # writing then chmod-ing: the gap between the two is a window where the
        # key is world-readable.
        descriptor = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(_KEY_COMMENT.encode("utf-8"))
            handle.write(pem)
        self.created = True
        return key

    def _warn_if_readable_by_others(self) -> None:
        """A signing key readable by other accounts is a signing key they hold."""
        try:
            mode = self.key_path.stat().st_mode
        except OSError:  # pragma: no cover - unreadable stat is not worth failing on
            return
        if mode & (stat.S_IRGRP | stat.S_IROTH):
            import sys

            print(  # noqa: T201 - startup diagnostic
                f"[audit] WARNING: signing key {self.key_path} is readable beyond its owner; "
                "anyone who can read it can forge audit records (chmod 600).",
                file=sys.stderr,
            )

    @property
    def key_id(self) -> str:
        """Short fingerprint of the public key, recorded on every signed event."""
        return public_key_fingerprint(self.public_key_pem())

    def sign(self, data: bytes) -> str:
        return base64.b64encode(self._private_key.sign(data)).decode("ascii")

    def public_key_pem(self) -> str:
        from cryptography.hazmat.primitives import serialization

        return (
            self._private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("ascii")
        )


def public_key_fingerprint(public_key_pem: str) -> str:
    """Stable short identifier for a public key."""
    if not public_key_pem:
        return ""
    digest = hashlib.sha256(public_key_pem.strip().encode("ascii")).hexdigest()
    return f"ed25519:{digest[:16]}"


def verify_signature(data: bytes, signature: str, public_key_pem: str) -> bool:
    """Check one signature against a public key. Never raises."""
    if not signature or not public_key_pem:
        return False
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            return False
        key.verify(base64.b64decode(signature), data)
        return True
    except Exception:  # noqa: BLE001 - any failure is a failed verification
        return False


def build_signer_from_settings() -> AuditSigner:
    """The configured signer, or :class:`NullSigner` when signing is disabled."""
    from src.config import get_settings

    settings = get_settings()
    if not settings.audit_signing_enabled:
        return NullSigner()

    try:
        return Ed25519Signer(settings.audit_signing_key_path)
    except Exception as exc:  # noqa: BLE001 - never let key trouble stop auditing
        import sys

        # Failing closed here would mean losing the audit trail entirely, which
        # is worse than losing signatures on it. The chain still protects
        # integrity; the loss of non-repudiation is announced rather than silent.
        print(  # noqa: T201 - startup diagnostic
            f"[audit] WARNING: signing disabled, key unavailable: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return NullSigner()
