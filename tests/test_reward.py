import pytest

from malware_rl.envs.reward import TierAwareReward, _default_check_func


def make_call(reward_fn, **overrides):
    """Helper: call __call__ with default input plus overrides."""
    defaults = dict(
        score=0.7,
        original_score=0.9,
        threshold=0.5,
        turn=2,
        maxturns=10,
        original_size=1000,
        current_size=1000,
        binary=b"\x00" * 100,
        tiers_used={1},
    )
    defaults.update(overrides)
    return reward_fn(**defaults)


class TestDefault:
    def test_default_check_func_returns_true(self):
        assert _default_check_func(b"anything") is True

    def test_no_evasion_no_inflation_default(self):
        reward, done = make_call(TierAwareReward())

        assert reward == pytest.approx(0.2)
        assert done is False
        assert isinstance(reward, float)
        assert isinstance(done, bool)

    def test_evasion_default(self):
        reward, done = make_call(TierAwareReward(), score=0.3)

        assert reward == pytest.approx(9.7 + 1 / 3)
        assert done is True
        assert isinstance(reward, float)
        assert isinstance(done, bool)


class TestRFunc:
    def test_broken_binary_penalty(self):
        reward_fn = TierAwareReward(check_func=lambda _: False)

        reward, done = make_call(reward_fn)

        assert reward == pytest.approx(0.2 - 15.0)
        assert done is False

    def test_broken_with_evasion_still_negative(self):
        reward_fn = TierAwareReward(check_func=lambda _: False)

        reward, done = make_call(reward_fn, score=0.3)

        assert reward < 0
        assert done is True

    def test_checker_exception_fail_safe(self):
        def bad_checker(binary):
            raise RuntimeError("simulated")

        reward_fn = TierAwareReward(check_func=bad_checker)

        with pytest.warns(UserWarning, match="check_func raised"):
            reward, done = make_call(reward_fn)

        assert reward == pytest.approx(0.2)
        assert done is False

    def test_lambda_f_tunable(self):
        reward_fn = TierAwareReward(lambda_f=50.0, check_func=lambda _: False)

        reward, done = make_call(reward_fn)

        assert reward == pytest.approx(0.2 - 50.0)
        assert done is False


class TestBackwardCompat:
    """R1: no-arg reward must match the previous 3-component behavior."""

    def test_no_func_does_not_affect_reward(self):
        reward_fn = TierAwareReward()

        reward, done = make_call(reward_fn)

        expected = 0.2 + 0.0 + 0.0
        assert reward == pytest.approx(expected)
        assert done is False