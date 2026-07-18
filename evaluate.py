import os
import random
import sys

import gym
import numpy as np
from gym import wrappers
from stable_baselines3 import PPO
import argparse

import malware_rl


def evaluate_model(agent_path, env_name, num_episodes, outdir, seed=0):
    """
    Evaluates a trained model on a given environment.
    """
    # Setting up testing parameters and holding variables
    # episode_count = 200
    done = False
    reward = 0
    evasions = 0
    evasion_history = {}

    print("[*] Evaluation phase begins")
    agent = PPO.load(agent_path)

    eval_env = gym.make(env_name)
    eval_env = wrappers.Monitor(eval_env, directory=outdir, force=True)
    eval_env.seed(seed)

    # Test the agent in the eval environment
    for i in range(num_episodes):
        ob = eval_env.reset()
        sha256 = eval_env.sha256
        while True:
            action, _ = agent.predict(ob, reward, done)
            ob, reward, done, ep_history = eval_env.step(action)
            if done and ep_history["evaded"]:
                evasions += 1
                evasion_history[sha256] = ep_history
                break
            elif done:
                break
    
    # Output metrics/evaluation stuff
    # Removed the skipped binaries
    print("History:", evasion_history)
    print("True episode count:", i+1)
    print("Skipped binaries: ", eval_env.skipped)
    total_episodes = num_episodes - eval_env.skipped
    # Output metrics/evaluation stuff
    evasion_rate = (evasions / total_episodes) * 100
    mean_action_count = np.mean(eval_env.get_episode_lengths())
    print(f"{evasion_rate}% samples evaded model.")
    print(f"Average of {mean_action_count} moves to evade model.")
        

def get_registered_env_sample_count(env_name):
    env_specs = gym.envs.registration.registry.env_specs
    if env_name not in env_specs:
        return None
    return len(env_specs[env_name]._kwargs["sha256list"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=["AV1", "custom"], default="custom")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--agent", type=str, default="saved_models/ppo-only-sorelFFNN-train-v0-26871.zip")
    parser.add_argument(
        "--num-episodes",
        type=int,
        default=None,
        help="Number of test episodes. Defaults to all samples in the registered test split.",
    )
    
    args = parser.parse_args()
    target = args.target
    seed = args.seed
    agent = args.agent
    random.seed(seed)
    module_path = os.path.split(os.path.abspath(sys.modules[__name__].__file__))[0]
    outdir = os.path.join(module_path, "data/logs/ppo-agent-results")

    test_env = f"{target}-test-v0"
    num_episodes = args.num_episodes
    if num_episodes is None:
        num_episodes = get_registered_env_sample_count(test_env) or 300
    evaluate_model(agent, test_env, num_episodes, outdir, seed)
