
import base64
import hashlib
import io
import json
import os
import secrets
import time
import uuid
from datetime import datetime
from pathlib import Path

import pyotp
import qrcode
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import (Flask, jsonify, redirect, render_template, request,
                   send_file, session, url_for)

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ── Storage ──────────────────────────────────────────────────────────────────
STORAGE = Path("./storage")
SECURE_DIR   = STORAGE / "secure"
INSECURE_DIR = STORAGE / "insecure"
AUDIT_FILE   = STORAGE / "audit.json"
QR_DIR       = STORAGE / "qr"

for d in [SECURE_DIR, INSECURE_DIR, QR_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ── OTP brute-force tracker ──────────────────────────────────────────────────
otp_attempts: dict[str, int] = {}
OTP_LIMIT = 5

# ── Audit Log ─────────────────────────────────────────────────────────────────

def log(action: str, filename: str, result: str, details: str = ""):
    entry = {
        "id": uuid.uuid4().hex[:8].upper(),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "filename": filename,
        "result": result,
        "details": details,
    }
    logs = _read_logs()
    logs.insert(0, entry)
    AUDIT_FILE.write_text(json.dumps(logs, indent=2))
    return entry


def _read_logs() -> list:
    if AUDIT_FILE.exists():
        try:
            return json.loads(AUDIT_FILE.read_text())
        except Exception:
            return []
    return []

# ── Crypto ────────────────────────────────────────────────────────────────────

def encrypt(data: bytes) -> tuple[bytes, bytes]:
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, data, None)
    return key, nonce + ct


def decrypt(key: bytes, blob: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)

# ── Session helpers ───────────────────────────────────────────────────────────

def _state() -> dict:
    return session.setdefault("tl", {})


def _set(k, v):
    s = _state()
    s[k] = v
    session["tl"] = s
    session.modified = True

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("transfer"))


@app.route("/transfer")
def transfer():
    s = _state()
    return render_template("upload.html",
                           uploaded=s.get("file_id"),
                           verified=s.get("otp_verified"),
                           tampered=s.get("tampered", False))


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify(error="No file selected"), 400

    data = f.read()
    key, blob = encrypt(data)

    file_id = uuid.uuid4().hex
    blob_path = SECURE_DIR / f"{file_id}.enc"
    blob_path.write_bytes(blob)

    totp_secret = pyotp.random_base32()

    # Generate QR
    uri = pyotp.TOTP(totp_secret).provisioning_uri(
        name="user@tradelock.io", issuer_name="TradeLock"
    )
    qr_img = qrcode.make(uri)
    qr_path = QR_DIR / f"{file_id}.png"
    qr_img.save(qr_path)

    session["tl"] = {
        "file_id": file_id,
        "filename": f.filename,
        "key": base64.b64encode(key).decode(),
        "totp_secret": totp_secret,
        "otp_verified": False,
        "tampered": False,
        "hex_preview": blob[12:72].hex(),
        "original_size": len(data),
        "encrypted_size": len(blob),
    }
    session.modified = True

    log("UPLOAD", f.filename, "SUCCESS",
        f"AES-256-GCM | {len(data)} → {len(blob)} bytes")

    return jsonify(
        file_id=file_id,
        filename=f.filename,
        hex_preview=blob[12:72].hex(),
        original_size=len(data),
        encrypted_size=len(blob),
    )


@app.route("/qr/<file_id>")
def qr(file_id):
    path = QR_DIR / f"{file_id}.png"
    if not path.exists():
        return "Not found", 404
    return send_file(path, mimetype="image/png")


@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    s = _state()
    code = request.json.get("code", "").strip()
    file_id = s.get("file_id", "anon")

    # Brute-force guard
    attempts = otp_attempts.get(file_id, 0)
    if attempts >= OTP_LIMIT:
        log("OTP_BRUTE_FORCE_BLOCKED", s.get("filename", "?"), "BLOCKED",
            f"Exceeded {OTP_LIMIT} attempts")
        return jsonify(ok=False,
                       message=f"🚫 Too many attempts. Access locked after {OTP_LIMIT} tries.")

    totp = pyotp.TOTP(s.get("totp_secret", ""))
    if totp.verify(code, valid_window=1):
        _set("otp_verified", True)
        otp_attempts.pop(file_id, None)
        log("OTP_VERIFY", s.get("filename", "?"), "SUCCESS", "TOTP verified")
        return jsonify(ok=True, message="✅ Identity verified. Download unlocked.")
    else:
        otp_attempts[file_id] = attempts + 1
        remaining = OTP_LIMIT - otp_attempts[file_id]
        log("OTP_VERIFY", s.get("filename", "?"), "FAILED",
            f"Invalid code | {otp_attempts[file_id]}/{OTP_LIMIT} attempts")
        return jsonify(ok=False,
                       message=f"❌ Invalid code. {remaining} attempt(s) remaining.")


@app.route("/download")
def download():
    s = _state()
    if not s.get("otp_verified"):
        return jsonify(error="2FA required"), 403

    file_id = s.get("file_id")
    blob_path = SECURE_DIR / f"{file_id}.enc"
    if not blob_path.exists():
        return jsonify(error="File not found"), 404

    key = base64.b64decode(s["key"])
    blob = blob_path.read_bytes()

    try:
        plaintext = decrypt(key, blob)
    except InvalidTag:
        log("INTEGRITY_FAIL", s.get("filename", "?"), "TAMPERED",
            "AES-GCM authentication tag mismatch")
        _set("otp_verified", False)
        return jsonify(error="tampered"), 422

    _set("otp_verified", False)
    log("DOWNLOAD", s.get("filename", "?"), "SUCCESS", "Decrypted and delivered")

    return send_file(
        io.BytesIO(plaintext),
        as_attachment=True,
        download_name=s.get("filename", "file"),
        mimetype="application/octet-stream",
    )


# ── Insecure Transfer ────────────────────────────────────────────────────────

@app.route("/insecure-upload", methods=["POST"])
def insecure_upload():
    """Store file as plain bytes — no encryption, no integrity check."""
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify(error="No file selected"), 400

    data = f.read()
    file_id = uuid.uuid4().hex
    path = INSECURE_DIR / f"{file_id}.raw"
    path.write_bytes(data)

    session["tl_insecure"] = {
        "file_id": file_id,
        "filename": f.filename,
        "size": len(data),
        "tampered": False,
    }
    session.modified = True

    log("INSECURE_UPLOAD", f.filename, "EXPOSED", f"Plaintext | {len(data)} bytes — no encryption")

    return jsonify(
        file_id=file_id,
        filename=f.filename,
        size=len(data),
        # Send a real preview of the raw bytes so the hacker view shows readable content
        preview=data[:120].decode("utf-8", errors="replace"),
    )


@app.route("/insecure-tamper", methods=["POST"])
def insecure_tamper():
    """Silently flip bytes in the plaintext file — victim gets no warning."""
    s = session.get("tl_insecure", {})
    file_id = s.get("file_id")
    if not file_id:
        return jsonify(ok=False, message="No insecure file uploaded yet.")

    path = INSECURE_DIR / f"{file_id}.raw"
    if not path.exists():
        return jsonify(ok=False, message="File not found.")

    data = bytearray(path.read_bytes())

    # Corrupt a range of bytes in the middle of the file
    start = min(20, len(data))
    end   = min(start + 30, len(data))
    original_slice = bytes(data[start:end]).decode("utf-8", errors="replace")
    for i in range(start, end):
        data[i] ^= 0xAA          # XOR with 0xAA — garbles text visibly
    corrupted_slice = bytes(data[start:end]).decode("utf-8", errors="replace")

    path.write_bytes(bytes(data))

    # Mark session but DON'T surface any integrity warning on download
    s["tampered"] = True
    session["tl_insecure"] = s
    session.modified = True

    log("INSECURE_TAMPER", s.get("filename", "?"), "SILENT",
        "Plaintext modified — no integrity check, victim unaware")

    return jsonify(
        ok=True,
        original=original_slice,
        corrupted=corrupted_slice,
        message="File silently corrupted. No integrity mechanism to detect this.",
    )


@app.route("/insecure-download")
def insecure_download():
    """Return the raw file with zero checks — tampered or not."""
    s = session.get("tl_insecure", {})
    file_id = s.get("file_id")
    if not file_id:
        return jsonify(error="No file"), 404

    path = INSECURE_DIR / f"{file_id}.raw"
    if not path.exists():
        return jsonify(error="File not found"), 404

    data = path.read_bytes()
    was_tampered = s.get("tampered", False)

    # Log — note: server knows it was tampered in this demo, but gives NO warning to user
    result = "DELIVERED_TAMPERED" if was_tampered else "SUCCESS"
    log("INSECURE_DOWNLOAD", s.get("filename", "?"), result,
        "No integrity check — corrupted file delivered silently" if was_tampered else "Plaintext delivered")

    # Deliver silently regardless of tampering — this is the point of the demo
    return send_file(
        io.BytesIO(data),
        as_attachment=True,
        download_name=s.get("filename", "file"),
        mimetype="application/octet-stream",
    )


# ── Attack Lab ────────────────────────────────────────────────────────────────

@app.route("/attack")
def attack():
    s = _state()
    return render_template("attack.html",
                           has_file=bool(s.get("file_id")),
                           tampered=s.get("tampered", False))


@app.route("/attack/tamper", methods=["POST"])
def tamper():
    s = _state()
    file_id = s.get("file_id")
    if not file_id:
        return jsonify(ok=False, message="No file uploaded yet.")

    path = SECURE_DIR / f"{file_id}.enc"
    if not path.exists():
        return jsonify(ok=False, message="Encrypted file not found.")

    blob = bytearray(path.read_bytes())
    # Flip a byte in the ciphertext (after 12-byte nonce)
    idx = 20
    original = blob[idx]
    blob[idx] ^= 0xFF
    path.write_bytes(bytes(blob))
    _set("tampered", True)

    log("TAMPER_ATTACK", s.get("filename", "?"), "EXECUTED",
        f"Byte {idx}: 0x{original:02X} → 0x{blob[idx]:02X}")

    return jsonify(
        ok=True,
        message="💣 File tampered! Byte flipped in ciphertext.",
        byte_index=idx,
        original=f"0x{original:02X}",
        modified=f"0x{blob[idx]:02X}",
    )


@app.route("/attack/brute-force", methods=["POST"])
def brute_force():
    s = _state()
    file_id = s.get("file_id", "demo")
    secret = s.get("totp_secret")

    results = []
    blocked_at = None

    for i in range(1, OTP_LIMIT + 3):
        fake_code = f"{secrets.randbelow(1000000):06d}"
        attempts = otp_attempts.get(file_id, 0)

        if attempts >= OTP_LIMIT:
            blocked_at = i
            results.append({"attempt": i, "code": fake_code, "status": "BLOCKED", "reason": "Rate limit exceeded"})
            log("OTP_BRUTE_FORCE", s.get("filename", "?"), "BLOCKED",
                f"Attempt {i} blocked")
            break

        if secret:
            totp = pyotp.TOTP(secret)
            valid = totp.verify(fake_code, valid_window=1)
        else:
            valid = False

        otp_attempts[file_id] = attempts + 1
        status = "VALID" if valid else "FAILED"
        results.append({"attempt": i, "code": fake_code, "status": status})

    return jsonify(
        results=results,
        blocked_at=blocked_at,
        message=f"🛡️ Attack blocked after {blocked_at} attempts. Rate limiting prevented brute force." if blocked_at else "Simulation complete.",
    )


@app.route("/attack/replay", methods=["POST"])
def replay():
    s = _state()
    secret = s.get("totp_secret")
    if not secret:
        return jsonify(ok=False, message="No active session to replay.")

    # Simulate replaying a "captured" OTP from 60 seconds ago
    totp = pyotp.TOTP(secret)
    # Use a code from 2 windows back (definitely expired)
    old_time = int(time.time()) - 90
    old_counter = old_time // 30
    import hmac
    import struct

    def hotp(secret_b32, counter):
        key = base64.b32decode(secret_b32.upper())
        msg = struct.pack(">Q", counter)
        h = hmac.new(key, msg, "sha1").digest()
        offset = h[-1] & 0x0F
        code = (int.from_bytes(h[offset:offset + 4], "big") & 0x7FFFFFFF) % 1000000
        return f"{code:06d}"

    captured_code = hotp(secret, old_counter)
    is_valid = totp.verify(captured_code, valid_window=0)  # strict window

    log("REPLAY_ATTACK", s.get("filename", "?"), "BLOCKED",
        f"Expired OTP {captured_code} rejected")

    return jsonify(
        captured_code=captured_code,
        accepted=is_valid,
        message="🔁 Replay attack failed — TOTP codes expire every 30 seconds.",
        explanation="The OTP captured 90 seconds ago is no longer valid. Time-based tokens prevent replay attacks.",
    )


# ── Audit ─────────────────────────────────────────────────────────────────────

@app.route("/audit")
def audit():
    logs = _read_logs()
    return render_template("audit.html", logs=logs)


@app.route("/audit/clear", methods=["POST"])
def clear_audit():
    AUDIT_FILE.write_text("[]")
    return redirect(url_for("audit"))


@app.route("/audit/data")
def audit_data():
    return jsonify(_read_logs())


if __name__ == "__main__":
    print("\n  TradeLock — starting on http://127.0.0.1:5000\n")
    app.run(debug=True, port=5000)
