import celery_worker

import logging
import time

time.sleep(20)
logging.basicConfig(level=logging.DEBUG)

#https://www.postgresqltutorial.com/postgresql-python
#docker exec -it docker_db_1 bash
#psql -h 127.0.0.1 -d secureuall -U frontend


def start_celery():
    try:
        ready=celery_worker.main.delay()

        #stay up
        while True:
            time.sleep(30)

    except:
        start_celery()
    

if __name__ == "__main__":
    start_celery()
    






