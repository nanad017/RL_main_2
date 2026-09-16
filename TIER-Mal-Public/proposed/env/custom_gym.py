import hashlib
import os
import random
from collections import OrderedDict

import gym
import numpy as np
from gym import spaces

from proposed.actions import modifier
from proposed.env.reward import TierAwareReward, get_action_tier
from proposed.paths import PROJECT_ROOT, RUNTIME_DIR
from proposed.utils import custom_api, interface

default_shared_root = str(RUNTIME_DIR / "share")

ACTION_LOOKUP = {i: act for i, act in enumerate(modifier.ACTION_TABLE.keys())}


class CustomDetectorEnv(gym.Env):
    metadata = {"render.modes": ["human"]}

    def __init__(
        self,
        sha256list,
        random_sample=True,
        maxturns=5,
        output_path="runtime/evaded/custom",
        save_modified_data=False,
        url_path="http://127.0.0.1:8000",
        shared_root=default_shared_root,
        threshold=0.5,
        reward_fn=None,
    ):
        super().__init__()
        self.available_sha256 = sha256list
        self.action_space = spaces.Discrete(len(ACTION_LOOKUP))
        observation_high = np.finfo(np.float32).max
        self.observation_space = spaces.Box(
            low=-observation_high,
            high=observation_high,
            shape=(2381,),
            dtype=np.float32,
        )
        self.observation = None
        self.maxturns = maxturns
        self.model = custom_api.CustomAPIModel(url_path, shared_root, threshold)
        self.threshold = threshold
        self.feature_extractor = self.model.extract
        self.output_path = output_path
        self.random_sample = random_sample
        self.history = OrderedDict()
        self.sample_iteration_index = 0
        self.queries = 0
        self.skipped = 0

        self.output_path = str(PROJECT_ROOT / output_path)
        self.save_data = save_modified_data
        if self.save_data:
            os.makedirs(self.output_path, exist_ok=True)

        self.reward_fn = reward_fn if reward_fn is not None else TierAwareReward()

    def step(self, action_ix):
        self.turns += 1
        action_name = self._take_action(action_ix)
        self.observation = self.feature_extractor(self.bytez)
        self.score = self.model.predict_sample(self.bytez, self.sha256)
        self.queries += 1

        self.tiers_used.add(get_action_tier(action_name))

        reward, episode_over = self.reward_fn(
            score=self.score,
            original_score=self.original_score,
            threshold=self.threshold,
            turn=self.turns,
            maxturns=self.maxturns,
            original_size=self.original_size,
            current_size=len(self.bytez),
            binary=self.bytez,
            tiers_used=self.tiers_used,
            action_name=action_name,
            action_context=self.action_context,
        )

        if episode_over:
            self.history[self.sha256]["evaded"] = self.score < self.threshold
            self.history[self.sha256]["reward"] = reward

            if self.score < self.threshold and self.save_data:
                m = hashlib.sha256()
                m.update(self.bytez)
                sha256 = m.hexdigest()
                evade_path = interface.get_evasion_output_path(
                    self.output_path,
                    self.sha256,
                    sha256,
                )
                with open(evade_path, "wb") as out:
                    out.write(self.bytez)
                self.history[self.sha256]["evade_path"] = evade_path

            print(
                f"Episode over: reward = {reward:.4f}, "
                f"tiers = {self.tiers_used}, "
                f"size_delta = {len(self.bytez) - self.original_size:+d}, "
                f"queries until now {self.queries}"
            )

        return self.observation, reward, episode_over, self.history[self.sha256]

    def _take_action(self, action_ix):
        action = ACTION_LOOKUP[int(action_ix)]
        self.history[self.sha256]["actions"].append(action)
        result = modifier.modify_sample_with_report(self.bytez, action)
        self.bytez = result.bytez
        self.action_context = result.action_context
        return action

    def reset(self):
        self.turns = 0
        self.tiers_used = set()
        self.action_context = None
        while True:
            if self.random_sample:
                self.sha256 = random.choice(self.available_sha256)
            else:
                self.sha256 = self.available_sha256[
                    self.sample_iteration_index % len(self.available_sha256)
                ]
                self.sample_iteration_index += 1

            self.history[self.sha256] = {"actions": [], "evaded": False}
            self.bytez = interface.fetch_sample(self.sha256)

            self.observation = self.feature_extractor(self.bytez)
            self.original_score = self.model.predict_sample(self.bytez, self.sha256)
            self.original_size = len(self.bytez)
            if self.original_score < self.threshold:
                self.skipped += 1
                continue

            break
        print(f"Sample: {self.sha256}")
        return self.observation

    def render(self, mode="human", close=False):
        pass
