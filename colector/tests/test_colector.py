from colector_main import Main
from Heartbeat import Heartbeat

from unittest.mock import MagicMock, call


def test_initialworker():
    Main.colector_topics=['INIT','SCAN_REQUEST','FRONTEND','LOG', 'HEARTBEAT', 'UPDATE']

    #Mock cursor
    cursor=MagicMock(fetchone=["0"])
    Main.conn= MagicMock(cursor=cursor)
    Main.producer = MagicMock()
    Main.initial_worker(Main,{"CONFIG":{"ADDRESS_LIST":["2.2.2"]}},bytes([2]))

    Main.conn.cursor.assert_called_once()
    cursor_calls=cursor.mock_calls

    assert(call().fetchone() in cursor_calls )
    assert(call().execute('''SELECT id FROM  machines_machine WHERE ip = %s or dns= %s''',("2.2.2","2.2.2")) in cursor_calls    )

def test_heartbeat():
    hb=Heartbeat()
    hb.startup()
    print(hb.workers)
    pass