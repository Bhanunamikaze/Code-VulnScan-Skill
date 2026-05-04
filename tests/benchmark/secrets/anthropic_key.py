# BENCHMARK: secrets - anthropic_api_key
# WARNING: This file contains a fake API key for benchmark testing only

import anthropic

API_KEY = "sk-ant-api03-fakekeyfortest1234567890abcdefghijklmnopqrstuvwxyz0123456789012345678901234"


def create_client():
    return anthropic.Anthropic(api_key=API_KEY)


def complete(prompt: str) -> str:
    client = create_client()
    message = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )
    return message.content[0].text
