#from __future__ import absolute_import
from celery import Celery
import celery_worker
from re import fullmatch
import logging
import time

time.sleep(20)
logging.basicConfig(level=logging.DEBUG)

logging.warning("Colector started")
#mongo_client = MongoClient("mongodb://localhost:27017/")
#print(mongo_client)


#https://www.postgresqltutorial.com/postgresql-python
#docker exec -it docker_db_1 bash
#psql -h 127.0.0.1 -d secureuall -U frontend




if __name__ == "__main__":
    ready=celery_worker.main.delay()





