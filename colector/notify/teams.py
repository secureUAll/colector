from __future__ import annotations

import json
import requests

from .notify import Notify


class TeamsNotify(Notify):

    def __init__(self):
        # <head>
        self._msg = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": "92d400",
            "summary": "",
            "title": "",
            "sections": [],
            "potentialAction": []
        }

    def heading(self, h1: str, end="\n") -> TeamsNotify:
        if not self._msg['sections']:
            self._msg['title'] = h1
        else:
            self._msg['sections'].append({
                "activityTitle": f"**{h1}**",
            })
        return self

    def heading2(self, h2: str, end="\n") -> TeamsNotify:
        self._msg['sections'].append({
            "activityTitle": f"*{h2}*",
        })
        return self

    def text(self, text: str, end="\n") -> TeamsNotify:
        self._msg['sections'].append({
            "text": text
        })
        return self

    def information(self, title: str, info: str, end="\n") -> TeamsNotify:
        self._msg['sections'].append({
            "activityTitle": f"**{title}** ",
            "activitySubtitle": info
        })
        return self

    def button(self, url: str, text:str, end="\n") -> TeamsNotify:
        self._msg['potentialAction'].append({
            "@type": "OpenUri",
            "name": text,
            "targets": [
                {
                    "os": "default",
                    "uri": url
                }
            ]
        })
        return self

    def card(self, title: str, content: list, end="\n") -> TeamsNotify:
        # Content is list of objects like {name: str, value: str}
        self._msg['sections'].append({
            "startGroup": True,
            "title": f"**{title}**",
            "facts": [
                {
                    "name": c["name"],
                    "value": c["value"]
                } for c in content
            ]
        })
        return self

    def _spacebelow(self) -> TeamsNotify:
        # This method is not implemented
        return self

    def bold(self, text) -> str:
        return f'**{text}**'

    def italic(self, text) -> str:
        return f'*{text}*'

    def __str__(self) -> str:
        return self._msg

    def clean(self) -> TeamsNotify:
        return TeamsNotify()

    def send(self, subject: str,   recipient: str, preview: str,):
        self._msg['summary'] = preview
        print("SENDING to", recipient)
        print()
        print(json.dumps(self._msg))
        print()
        r = requests.post(recipient, data=json.dumps(self._msg))
        return r.status_code
