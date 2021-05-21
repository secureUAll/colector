from colector_main import Main
from Heartbeat import Heartbeat
from unittest.mock import patch
from unittest.mock import MagicMock

def test_initialworker():
    Main.colector_topics=['INIT','SCAN_REQUEST','FRONTEND','LOG', 'HEARTBEAT', 'UPDATE']
    Main.conn= MagicMock()
    Main.producer = MagicMock()
    Main.initial_worker(Main,{"CONFIG":{"ADDRESS_LIST":["2.2.2"]}},bytes([2]))

def test_heartbeat():
    hb=Heartbeat()
    hb.startup()
    print(hb.workers)
    pass