import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import gym
from stable_baselines3.common.env_checker import check_env

import proposed  # Registers the reorganized Gym environments.


def test_env(env_name):

    print(f"TESTING {env_name}!")
    env = gym.make(env_name)
    print("Checking environment . . .")
    check_env(env)
    env.close()


environments = ["custom-train-v0", "custom-test-v0"]

for e in environments:
    test_env(e)
