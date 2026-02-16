import json
import os

class Config:
    DEFAULT_CONFIG = {
        "scan_types": ["headers", "xss", "sqli", "csrf", "sast"],
        "threads": 4,
        "timeout": 10,
        "user_agent": "BugFinder/1.0",
        "output_dir": "reports",
        "interactive": False
    }

    def __init__(self, config_path=None):
        self.config = self.DEFAULT_CONFIG.copy()
        if config_path and os.path.exists(config_path):
            self.load_config(config_path)

    def load_config(self, path):
        try:
            with open(path, 'r') as f:
                user_config = json.load(f)
                self.config.update(user_config)
        except Exception as e:
            print(f"Error loading config: {e}")

    def get(self, key):
        return self.config.get(key)

    def set(self, key, value):
        self.config[key] = value

    def save_config(self, path):
        try:
            with open(path, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            print(f"Error saving config: {e}")
