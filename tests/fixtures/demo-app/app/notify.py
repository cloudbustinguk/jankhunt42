"""Outbound notifications and summaries."""
import requests
from openai import OpenAI

client = OpenAI()


def announce(text: str) -> None:
    requests.post("https://hooks.chat.example.com/services/demo", json={"text": text}, timeout=5)


def summarize(rows: list) -> str:
    reply = client.responses.create(model="demo-model", input=str(rows))
    return reply.output_text
