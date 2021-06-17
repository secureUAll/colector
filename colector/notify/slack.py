from __future__ import annotations

import json

from .notify import Notify
import requests


class SlackNotify(Notify):

    SLACK = "https://hooks.slack.com/services/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"

    def __init__(self):
        self._text = ""

    # INSERT methods
    def heading(self, h1: str, end="\n") -> SlackNotify:
        self._text += f"*{h1}*{end}"
        return self

    def heading2(self, h2: str, end="\n") -> SlackNotify:
        return self.heading(h2)

    def text(self, text: str, end="\n") -> SlackNotify:
        self._text += f"{text}{end}"
        return self

    def olist(self, lst: list) -> SlackNotify:
        for i in range(1, lst+1):
            self._text += f" {i}. {lst[i]}\n"
        return self

    def ulist(self, lst: list) -> SlackNotify:
        for l in lst:
            self._text += f" - {l}\n"
        return self

    def citation(self, citation: str, end="\n") -> SlackNotify:
        self._text += f"> {citation}{end}"
        return self

    def code(self, block: str) -> SlackNotify:
        self._text += f"```\n{block}\n```\n"
        return self

    def url(self, url: str, end="\n") -> SlackNotify:
        self._text += f"{url}{end}"
        return self

    def brake(self) -> SlackNotify:
        self._text += "\n"
        return self

    # DECORATION methods
    def bold(self, text: str) -> str:
        return f"*{text}*"

    def italic(self, text: str) -> str:
        return f"_{text}_"

    def label(self, text: str, end="\n") -> SlackNotify:
        self._text += f"`{text}`{end}"
        return self

    # PARSING
    def __str__(self) -> str:
        return self._text

    # SEND methods
    def send(self, recipients: list) -> int:
        message = "NEW MESSAGE\n"
        message += f"\nRecipients: {'; '.join(recipients)}\n"
        message += "\nMessage ---------------------\n\n"
        message += self._text
        message += "\n--------------------- End Message\n"
        r = requests.post(SlackNotify.SLACK, data=json.dumps({'text': message}))

        print("MESSAGE", json.dumps({'text': message}))

        print("TEXT", r.text)
        return r.status_code

