"""Tests for lib/funcval/bounds.py — the pure-python bounds math.

These tests pin the Clopper-Pearson upper bound against KNOWN values:
  - the k=0 closed form  cp(0,n,delta) == 1 - delta**(1/n)
  - tabulated k>0 values at delta=0.05
  - monotonicity (increasing in k, decreasing in n at k=0)
and pin the Boole/union-bound combiner.
"""
from __future__ import annotations

import math

import pytest

from funcval.bounds import clopper_pearson_upper, union_bound


# --- Clopper-Pearson: k == 0 closed form -----------------------------------
# For k=0 the (1-delta) quantile of Beta(1, n) has the closed form
# 1 - delta**(1/n).  We assert the implementation matches it.

def test_cp_k0_n256_closed_form():
    got = clopper_pearson_upper(0, 256, 0.05)
    closed = 1 - 0.05 ** (1 / 256)
    assert got == pytest.approx(closed, abs=1e-3)
    # spec target
    assert got == pytest.approx(0.011626, abs=1e-3)


def test_cp_k0_n100_closed_form():
    got = clopper_pearson_upper(0, 100, 0.05)
    closed = 1 - 0.05 ** (1 / 100)
    assert got == pytest.approx(closed, abs=1e-3)
    assert got == pytest.approx(0.029513, abs=1e-3)


def test_cp_k0_n300_closed_form():
    got = clopper_pearson_upper(0, 300, 0.05)
    closed = 1 - 0.05 ** (1 / 300)
    assert got == pytest.approx(closed, abs=1e-3)


# --- Clopper-Pearson: k == n  -> certain failure -> 1.0 --------------------

@pytest.mark.parametrize("n", [1, 5])
def test_cp_k_equals_n_is_one(n):
    assert clopper_pearson_upper(n, n, 0.05) == 1.0


# --- Clopper-Pearson: tabulated k>0 values ---------------------------------

def test_cp_1_of_100():
    assert clopper_pearson_upper(1, 100, 0.05) == pytest.approx(0.0466, abs=1e-3)


def test_cp_5_of_100():
    # The exact (1-delta)=0.95 quantile of Beta(6, 95) is 0.102253...
    # The brief's "~0.1035" is the 0.9538 quantile (a slightly different
    # confidence level); two independent definitions confirm 0.10225 is the
    # value for the stated definition:
    #   (a) Beta-quantile:  I_{0.10225}(6, 95) == 0.95 exactly.
    #   (b) binomial tail:  the p solving sum_{i=0}^{5} C(100,i) p^i (1-p)^95
    #                       == 0.05 is also 0.10225.
    # We assert the mathematically correct value, not the brief's approximation.
    assert clopper_pearson_upper(5, 100, 0.05) == pytest.approx(0.10225, abs=1e-3)


# --- Monotonicity ----------------------------------------------------------

def test_cp_increases_with_k():
    n, delta = 100, 0.05
    prev = -1.0
    for k in range(0, 11):
        b = clopper_pearson_upper(k, n, delta)
        assert b > prev, f"bound not increasing at k={k}: {b} <= {prev}"
        prev = b


def test_cp_decreases_with_n_at_k0():
    delta = 0.05
    prev = math.inf
    for n in (50, 100, 200, 400, 800):
        b = clopper_pearson_upper(0, n, delta)
        assert b < prev, f"bound not decreasing at n={n}: {b} >= {prev}"
        prev = b


def test_cp_bound_in_unit_interval():
    for k, n in [(0, 10), (3, 10), (10, 10), (0, 1000), (50, 1000)]:
        b = clopper_pearson_upper(k, n, 0.05)
        assert 0.0 <= b <= 1.0


# --- union_bound (Boole) ---------------------------------------------------

def test_union_bound_sum():
    assert union_bound([0.01, 0.02, 0.03]) == pytest.approx(0.06)


def test_union_bound_caps_at_one():
    assert union_bound([0.7, 0.7]) == 1.0


def test_union_bound_empty_is_zero():
    assert union_bound([]) == 0.0
