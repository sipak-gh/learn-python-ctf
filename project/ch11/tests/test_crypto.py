import random

import pytest

from ctfkit import crypto as c


def test_single_byte_xor_break():
    pt = b"The quick brown fox jumps over the lazy dog and runs away."
    ct = c.single_byte_xor(pt, 0x5A)
    key, recovered, _ = c.break_single_byte_xor(ct)
    assert key == 0x5A
    assert recovered == pt


def test_repeating_key_xor_break():
    pt = (b"When in the course of human events it becomes necessary for one "
          b"people to dissolve the political bands which have connected them.")
    key = b"ICE"
    ct = c.single_byte_xor  # noqa: F841  (keep import usage obvious)
    from ctfkit.encoding import xor
    ct = xor(pt, key)
    found_key, recovered = c.break_repeating_key_xor(ct, keysize=3)
    assert found_key == key
    assert recovered == pt


def test_modinv_and_egcd():
    assert c.modinv(3, 11) == 4
    g, x, y = c.egcd(240, 46)
    assert 240 * x + 46 * y == g == 2


def test_iroot_and_cube_root():
    assert c.iroot(27, 3) == (3, True)
    assert c.iroot(28, 3) == (3, False)
    assert c.cube_root(8) == (2, True)


def test_fermat_factor_balanced():
    p, q = 1000003, 1000033
    p2, q2 = c.factor_fermat(p * q)
    assert {p2, q2} == {p, q}


def test_rsa_prime_modulus_attack():
    # n prime -> phi = n-1
    n = 2**127 - 1  # a Mersenne prime
    e_ = 65537
    m = int.from_bytes(b"flag{hi}", "big")
    ct = pow(m, e_, n)
    assert c.rsa_attack_prime_modulus(ct, e_, n) == b"flag{hi}"


def test_rsa_small_e_cube_root():
    m = int.from_bytes(b"short-secret", "big")
    ct = m**3  # no modular reduction
    assert c.rsa_attack_small_e(ct, 3) == b"short-secret"


def test_mt19937_predicts_getrandbits():
    random.seed(20240101)
    outs = [random.getrandbits(32) for _ in range(624)]
    mt = c.MT19937.from_outputs(outs)
    predicted = [mt.next_u32() for _ in range(10)]
    actual = [random.getrandbits(32) for _ in range(10)]
    assert predicted == actual


def test_mt19937_from_seed_matches_cpython():
    mine = c.MT19937.from_seed(42)
    random.seed(42)
    assert [mine.random() for _ in range(5)] == [random.random() for _ in range(5)]


def test_untemper_is_inverse_of_temper():
    def temper(y):
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        return y & 0xFFFFFFFF

    for v in [0, 1, 0xFFFFFFFF, 0xDEADBEEF, 123456789]:
        assert c.untemper(temper(v)) == v


def test_lfsr_recover_state_round_trips():
    taps, width, secret = [0, 2], 5, [1, 0, 1, 1, 0]
    outputs = c.LFSR(list(secret), taps).bits(width)
    recovered = c.LFSR.recover_state(outputs, taps, width)
    assert recovered == secret  # reversed shift-out order, not outputs as-is
    clone = c.LFSR(recovered, taps)
    clone.bits(width)
    truth = c.LFSR(list(secret), taps)
    truth.bits(width)
    assert clone.bits(8) == truth.bits(8)
