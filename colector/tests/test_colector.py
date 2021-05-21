import colector_main
from unittest.mock import patch
from unittest.mock import MagicMock
"""
@patch('main.Main.conn', MagicMock())
@patch('main.Main.producer', MagicMock())
def test_initialworker():
    m=main.Main()
    m.initial_worker({"CONFIG":{"ADDRESS_LIST":["2.2.2"]}},bytes([2]))

"""