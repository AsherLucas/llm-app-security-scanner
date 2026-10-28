"""DELIBERATELY VULNERABLE EXAMPLE — do not copy this pattern.

The scanner should flag: a literal secret, shell=True on user input,
a file write to a user-controlled path, and untrusted input fed straight
into an LLM/agent prompt.
"""
import os
import subprocess

import requests

API_KEY = "sk-abcdefghijklmnopqrstuvwxyz1234567890"
AGENT_API_KEY = "sk-abcdefghijklmnopqrstuvwxyz1234567890"


def run_agent(user_input):
    # Untrusted web content + user input, straight into the prompt.
    page = requests.get("https://example.com/docs").text
    prompt = f"You are a helpful agent. User says: {user_input}\nWeb page says: {page}"
    llm = FakeLLM()
    return llm.generate(prompt)


def run_tool(user_input):
    # Shell without any allowlist, on user input.
    subprocess.run(user_input, shell=True)
    os.system(user_input)


def save_note(path, text):
    # File write to a user-controlled path, no directory confinement.
    with open(path, "w") as f:
        f.write(text)


class FakeLLM:
    def generate(self, prompt):
        return f"answered: {prompt}"
