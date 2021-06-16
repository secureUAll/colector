from __future__ import annotations
from abc import ABC, abstractmethod

"""
This class defines the interface for notification services

The methods (text, olist, ulist and citation) must implement parsing of the following elements:
- Labels: `this is a label`
- Bold: **This is bold text**
- Italic: *This is bold text* 
"""


class Notify(ABC):

    # INSERT methods
    @abstractmethod
    def heading(self, h1: str, end="\n") -> Notify:
        pass

    @abstractmethod
    def heading2(self, h2: str, end="\n") -> Notify:
        pass

    @abstractmethod
    def text(self, text: str, end="\n") -> Notify:
        pass

    @abstractmethod
    def information(self, title: str, info: str, end="\n") -> Notify:
        pass

    @abstractmethod
    def button(self, url: str, text: str, end="\n") -> Notify:
        pass

    @abstractmethod
    def card(self, title: str, content: list, end="\n") -> Notify:
        pass

    @abstractmethod
    def _spacebelow(self) -> Notify:
        pass

    @abstractmethod
    def clean(self) ->Notify:
        pass

    # DECORATION methods
    @staticmethod
    def bold(text :str, end="\n") -> str:
        pass

    @staticmethod
    def italic(text: str, end="\n") -> str:
        pass

    # PARSING
    @abstractmethod
    def __str__(self) -> str:
        pass

    # SEND methods
    @abstractmethod
    def send(self, subject: str, preview: str, recipient: str) -> int:
        pass
