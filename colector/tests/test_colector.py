import celery_worker
from unittest.mock import patch
from unittest.mock import MagicMock

@patch('celery_worker.conn', MagicMock())
@patch('celery_worker.producer', MagicMock())
def test_initialworker():
    celery_worker.initial_worker({"CONFIG":{"ADDRESS_LIST":["2.2.2"]}},bytes([2]))