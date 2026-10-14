"""WBSK two-layer white-box AES-256 envelope for the CN BYD app.

Ported from BYD-re/wbsk.js. The CN app (``com.byd.aeri.caranywhere``)
uses a two-layer white-box AES-256 envelope instead of the Bangcle
envelope used by the overseas app.

Envelope format: Base64 of ``version_byte(0x93) + IV(16) + ciphertext``,
with two nested WBC AES-256-CBC layers and per-byte nibble substitution
between the plaintext and WBC encoded domain.
"""

from __future__ import annotations

import base64
import struct

from pybyd._crypto._pkcs7 import strip_pkcs7
from pybyd._crypto._wbsk_tables import ENCODED_TABLES, WBSK_KEYS
from pybyd.exceptions import BydCryptoError

_NIBBLE_ENCODE = (0x0, 0x8, 0x4, 0xC, 0x1, 0x9, 0x5, 0xD, 0x2, 0xA, 0x6, 0xE, 0x3, 0xB, 0x7, 0xF)
_NIBBLE_DECODE = (0x0, 0x4, 0x8, 0xC, 0x2, 0x6, 0xA, 0xE, 0x1, 0x5, 0x9, 0xD, 0x3, 0x7, 0xB, 0xF)

# "Mystery encode": per-nibble ENCODE[ENCODE[n ^ 8]]
_MYSTERY_ENCODE = tuple(_NIBBLE_ENCODE[_NIBBLE_ENCODE[n ^ 8]] for n in range(16))

# ShiftRows / InvShiftRows permutations
_SR = (0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11)
_INV_SR = (0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3)

# T-table index patterns
_TE0_IDX = (0, 4, 8, 12)
_TE1_IDX = (5, 9, 13, 1)
_TE2_IDX = (10, 14, 2, 6)
_TE3_IDX = (15, 3, 7, 11)
_TD0_IDX = (0, 4, 8, 12)
_TD1_IDX = (13, 1, 5, 9)
_TD2_IDX = (10, 14, 2, 6)
_TD3_IDX = (7, 11, 15, 3)


def _decode_byte_table(name: str) -> bytes:
    raw = base64.b64decode(ENCODED_TABLES[name])
    if len(raw) != 256:
        raise BydCryptoError(f"WBSK table {name} has unexpected size {len(raw)} (expected 256)")
    return raw


def _decode_u32_table(name: str) -> tuple[int, ...]:
    raw = base64.b64decode(ENCODED_TABLES[name])
    if len(raw) != 1024:
        raise BydCryptoError(f"WBSK table {name} has unexpected size {len(raw)} (expected 1024)")
    result: list[int] = []
    for i in range(256):
        v = struct.unpack_from("<I", raw, i * 4)[0]
        if v >= 0x80000000:
            v -= 0x100000000
        result.append(v)
    return tuple(result)


def _prot_xor(table: bytes, a: int, b: int) -> int:
    hi = table[((a >> 4) << 4) ^ (b >> 4)] & 0xF0
    lo = (table[((a & 0xF) << 4) ^ (b & 0xF)] >> 4) & 0x0F
    return hi | lo


def _nibble_encode(buf: bytes) -> bytes:
    return bytes((_NIBBLE_ENCODE[b >> 4] << 4) | _NIBBLE_ENCODE[b & 0xF] for b in buf)


def _nibble_decode(buf: bytes) -> bytes:
    return bytes((_NIBBLE_DECODE[b >> 4] << 4) | _NIBBLE_DECODE[b & 0xF] for b in buf)


def _wbc_input_encode(buf: bytes) -> bytes:
    return bytes((_MYSTERY_ENCODE[b >> 4] << 4) | _MYSTERY_ENCODE[b & 0xF] for b in buf)


def _wbc_output_decode(buf: bytes) -> bytes:
    return bytes(
        (_NIBBLE_ENCODE[_NIBBLE_ENCODE[b >> 4]] << 4) | _NIBBLE_ENCODE[_NIBBLE_ENCODE[b & 0xF]]
        for b in buf
    )


def _add_wbc_pkcs7(buf: bytes, block_size: int = 16) -> bytes:
    remainder = len(buf) % block_size
    pad_n = block_size if remainder == 0 else block_size - remainder
    pad_byte = (_MYSTERY_ENCODE[pad_n >> 4] << 4) | _MYSTERY_ENCODE[pad_n & 0xF]
    return buf + bytes([pad_byte] * pad_n)


def _parse_wbc_key(hex_str: str) -> tuple[bytes, int, int]:
    raw = bytes.fromhex(hex_str)
    if len(raw) < 5:
        raise BydCryptoError(f"WBC key blob too short: {len(raw)} bytes")

    mode = raw[0] ^ raw[3]
    key_data = bytearray(len(raw) - 4)
    for i in range(4, len(raw)):
        key_data[i - 4] = raw[i] ^ raw[i % 3]

    _MODE_TO_BITS = {
        0: 0x80, 1: 0x80, 2: 0xC0, 3: 0xC0, 4: 0x80, 5: 0x80,
        6: 0x40, 7: 0x40, 8: 0xC0, 9: 0xC0, 0xA: 0x80, 0xB: 0x80,
        0xC: 0x80, 0xD: 0x80, 0xE: 0xC0, 0xF: 0xC0,
        0x10: 0x100, 0x11: 0x100, 0x12: 0x40, 0x13: 0x40,
        0x14: 0xC0, 0x15: 0xC0, 0x16: 0x80, 0x17: 0x80,
    }
    key_size_bits = _MODE_TO_BITS.get(mode)
    if key_size_bits is None:
        raise BydCryptoError(f"Unknown WBC mode: 0x{mode:x}")

    num_rounds = (key_size_bits >> 5) + 6
    return bytes(key_data), num_rounds, mode


class _WbskTables:
    __slots__ = (
        "enc_init_xor", "enc_round_xor", "enc_sbox", "enc_final_xor",
        "enc_te0", "enc_te1", "enc_te2", "enc_te3",
        "dec_init_xor", "dec_round_xor", "dec_inv_sbox", "dec_final_xor",
        "dec_td0", "dec_td1", "dec_td2", "dec_td3",
    )

    def __init__(self) -> None:
        self.enc_init_xor = _decode_byte_table("encInitXor")
        self.enc_round_xor = _decode_byte_table("encRoundXor")
        self.enc_sbox = _decode_byte_table("encSbox")
        self.enc_final_xor = _decode_byte_table("encFinalXor")
        self.enc_te0 = _decode_u32_table("encTe0")
        self.enc_te1 = _decode_u32_table("encTe1")
        self.enc_te2 = _decode_u32_table("encTe2")
        self.enc_te3 = _decode_u32_table("encTe3")
        self.dec_init_xor = _decode_byte_table("decInitXor")
        self.dec_round_xor = _decode_byte_table("decRoundXor")
        self.dec_inv_sbox = _decode_byte_table("decInvSbox")
        self.dec_final_xor = _decode_byte_table("decFinalXor")
        self.dec_td0 = _decode_u32_table("decTd0")
        self.dec_td1 = _decode_u32_table("decTd1")
        self.dec_td2 = _decode_u32_table("decTd2")
        self.dec_td3 = _decode_u32_table("decTd3")


_tables: _WbskTables | None = None


def _get_tables() -> _WbskTables:
    global _tables
    if _tables is None:
        _tables = _WbskTables()
    return _tables


def _wbc_encrypt_block(data: bytes, key_data: bytes, num_rounds: int, t: _WbskTables) -> bytes:
    state = bytearray(16)
    temp1 = bytearray(16)
    temp2 = bytearray(16)

    for i in range(16):
        state[i] = _prot_xor(t.enc_init_xor, data[i], key_data[i])

    for r in range(1, num_rounds):
        for c in range(4):
            v = t.enc_te0[state[c * 4]]
            temp1[c * 4] = (v >> 24) & 0xFF
            temp1[c * 4 + 1] = (v >> 16) & 0xFF
            temp1[c * 4 + 2] = (v >> 8) & 0xFF
            temp1[c * 4 + 3] = v & 0xFF
        for c in range(4):
            v = t.enc_te1[state[_TE1_IDX[c]]]
            temp2[c * 4] = (v >> 24) & 0xFF
            temp2[c * 4 + 1] = (v >> 16) & 0xFF
            temp2[c * 4 + 2] = (v >> 8) & 0xFF
            temp2[c * 4 + 3] = v & 0xFF
        for i in range(16):
            temp1[i] = _prot_xor(t.enc_round_xor, temp1[i], temp2[i])
        for c in range(4):
            v = t.enc_te2[state[_TE2_IDX[c]]]
            temp2[c * 4] = (v >> 24) & 0xFF
            temp2[c * 4 + 1] = (v >> 16) & 0xFF
            temp2[c * 4 + 2] = (v >> 8) & 0xFF
            temp2[c * 4 + 3] = v & 0xFF
        for i in range(16):
            temp1[i] = _prot_xor(t.enc_round_xor, temp1[i], temp2[i])
        for c in range(4):
            v = t.enc_te3[state[_TE3_IDX[c]]]
            temp2[c * 4] = (v >> 24) & 0xFF
            temp2[c * 4 + 1] = (v >> 16) & 0xFF
            temp2[c * 4 + 2] = (v >> 8) & 0xFF
            temp2[c * 4 + 3] = v & 0xFF
        for i in range(16):
            temp1[i] = _prot_xor(t.enc_round_xor, temp1[i], temp2[i])
        rk_off = r * 16
        for i in range(16):
            state[i] = _prot_xor(t.enc_round_xor, temp1[i], key_data[rk_off + i])

    for i in range(16):
        temp1[i] = t.enc_sbox[state[_SR[i]]]
    output = bytearray(16)
    frk_off = num_rounds * 16
    for i in range(16):
        output[i] = _prot_xor(t.enc_final_xor, temp1[i], key_data[frk_off + i])
    return bytes(output)


def _wbc_decrypt_block(data: bytes, key_data: bytes, num_rounds: int, t: _WbskTables) -> bytes:
    state = bytearray(16)
    temp1 = bytearray(16)
    temp2 = bytearray(16)

    for i in range(16):
        state[i] = _prot_xor(t.dec_init_xor, data[i], key_data[i])

    for r in range(1, num_rounds):
        for c in range(4):
            v = t.dec_td0[state[c * 4]]
            temp1[c * 4] = (v >> 24) & 0xFF
            temp1[c * 4 + 1] = (v >> 16) & 0xFF
            temp1[c * 4 + 2] = (v >> 8) & 0xFF
            temp1[c * 4 + 3] = v & 0xFF
        for c in range(4):
            v = t.dec_td1[state[_TD1_IDX[c]]]
            temp2[c * 4] = (v >> 24) & 0xFF
            temp2[c * 4 + 1] = (v >> 16) & 0xFF
            temp2[c * 4 + 2] = (v >> 8) & 0xFF
            temp2[c * 4 + 3] = v & 0xFF
        for i in range(16):
            temp1[i] = _prot_xor(t.dec_round_xor, temp1[i], temp2[i])
        for c in range(4):
            v = t.dec_td2[state[_TD2_IDX[c]]]
            temp2[c * 4] = (v >> 24) & 0xFF
            temp2[c * 4 + 1] = (v >> 16) & 0xFF
            temp2[c * 4 + 2] = (v >> 8) & 0xFF
            temp2[c * 4 + 3] = v & 0xFF
        for i in range(16):
            temp1[i] = _prot_xor(t.dec_round_xor, temp1[i], temp2[i])
        for c in range(4):
            v = t.dec_td3[state[_TD3_IDX[c]]]
            temp2[c * 4] = (v >> 24) & 0xFF
            temp2[c * 4 + 1] = (v >> 16) & 0xFF
            temp2[c * 4 + 2] = (v >> 8) & 0xFF
            temp2[c * 4 + 3] = v & 0xFF
        for i in range(16):
            temp1[i] = _prot_xor(t.dec_round_xor, temp1[i], temp2[i])
        rk_off = r * 16
        for i in range(16):
            state[i] = _prot_xor(t.dec_round_xor, temp1[i], key_data[rk_off + i])

    for i in range(16):
        temp1[i] = t.dec_inv_sbox[state[_INV_SR[i]]]
    output = bytearray(16)
    frk_off = num_rounds * 16
    for i in range(16):
        output[i] = _prot_xor(t.dec_final_xor, temp1[i], key_data[frk_off + i])
    return bytes(output)


def _wbc_encrypt_cbc(plaintext: bytes, key_data: bytes, num_rounds: int, iv: bytes, t: _WbskTables) -> bytes:
    block_count = len(plaintext) // 16
    output = bytearray(len(plaintext))
    prev = iv
    for b in range(block_count):
        block = bytes(plaintext[b * 16 + i] ^ prev[i] for i in range(16))
        enc = _wbc_encrypt_block(block, key_data, num_rounds, t)
        output[b * 16:b * 16 + 16] = enc
        prev = enc
    return bytes(output)


def _wbc_decrypt_cbc(ciphertext: bytes, key_data: bytes, num_rounds: int, iv: bytes, t: _WbskTables) -> bytes:
    block_count = len(ciphertext) // 16
    output = bytearray(len(ciphertext))
    prev = iv
    for b in range(block_count):
        block = ciphertext[b * 16:b * 16 + 16]
        dec = _wbc_decrypt_block(block, key_data, num_rounds, t)
        for i in range(16):
            output[b * 16 + i] = dec[i] ^ prev[i]
        prev = block
    return bytes(output)


class WbskCodec:
    """Encode and decode WBSK two-layer white-box AES-256 envelopes."""

    def __init__(self) -> None:
        self._t: _WbskTables | None = None

    def _ensure_tables(self) -> _WbskTables:
        if self._t is None:
            self._t = _get_tables()
        return self._t

    def encrypt_envelope(self, plaintext: str) -> str:
        """Encrypt plaintext into a WBSK envelope (Base64 string)."""
        t = self._ensure_tables()
        plain_buf = plaintext.encode("utf-8")
        inner_padded = _add_wbc_pkcs7(_wbc_input_encode(plain_buf))

        inner_key_data, inner_rounds, _ = _parse_wbc_key(WBSK_KEYS["innerEncryptKey"])
        inner_iv = bytes.fromhex(WBSK_KEYS["innerEncryptIv"])
        inner_encrypted = _wbc_encrypt_cbc(inner_padded, inner_key_data, inner_rounds, inner_iv, t)

        inner_raw = _wbc_output_decode(inner_encrypted)
        inner_b64 = base64.b64encode(inner_raw).decode("ascii")

        outer_content_plain = inner_b64.encode("latin-1") + _wbc_output_decode(inner_iv)
        outer_mystery = _add_wbc_pkcs7(_wbc_input_encode(outer_content_plain))

        outer_key_data, outer_rounds, _ = _parse_wbc_key(WBSK_KEYS["outerEncryptKey"])
        outer_iv = bytes.fromhex(WBSK_KEYS["outerEncryptIv"])
        outer_encrypted = _wbc_encrypt_cbc(outer_mystery, outer_key_data, outer_rounds, outer_iv, t)

        return base64.b64encode(_wbc_output_decode(outer_encrypted)).decode("ascii")

    def decrypt_envelope(self, base64_str: str) -> str:
        """Decrypt a WBSK envelope back to plaintext UTF-8 string."""
        t = self._ensure_tables()
        raw = base64.b64decode(base64_str)

        outer_encoded = _nibble_encode(raw) + bytes(256)
        outer_key_data, outer_rounds, _ = _parse_wbc_key(WBSK_KEYS["outerDecryptKey"])
        outer_iv = bytes.fromhex(WBSK_KEYS["outerDecryptIv"])
        outer_decrypted = _wbc_decrypt_cbc(outer_encoded, outer_key_data, outer_rounds, outer_iv, t)

        outer_content = strip_pkcs7(_nibble_decode(outer_decrypted[:len(raw)]))
        content_len = len(outer_content)

        inner_b64 = outer_content[:content_len - 16].decode("latin-1")
        inner_iv = outer_decrypted[content_len - 16:content_len]

        inner_raw = base64.b64decode(inner_b64)
        inner_encoded = _nibble_encode(inner_raw) + bytes(256)
        inner_key_data, inner_rounds, _ = _parse_wbc_key(WBSK_KEYS["innerDecryptKey"])
        inner_decrypted = _wbc_decrypt_cbc(inner_encoded, inner_key_data, inner_rounds, inner_iv, t)

        inner_content = strip_pkcs7(_nibble_decode(inner_decrypted[:len(inner_raw)]))
        return inner_content.decode("utf-8")
    async def async_load_tables(self) -> None:
        """No-op for interface compatibility with BangcleCodec."""
        self._ensure_tables()

    def encode_envelope(self, plaintext: str | bytes) -> str:
        """Encode envelope (interface compatible with BangcleCodec)."""
        if isinstance(plaintext, bytes):
            plaintext = plaintext.decode("utf-8")
        return self.encrypt_envelope(plaintext)

    def decode_envelope(self, envelope: str) -> bytes:
        """Decode envelope (interface compatible with BangcleCodec)."""
        return self.decrypt_envelope(envelope).encode("utf-8")