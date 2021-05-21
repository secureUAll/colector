import logging
from connections import connect_kafka_producer, connect_postgres, connect_redis
import json

class Heartbeat():
    def __init__(self):
        self.producer=connect_kafka_producer()
        self.postgre=connect_postgres()
        self.redis=connect_redis()
        self.redis.set("waiting_workers", str([]))
        self.workers=[]

    def startup(self):
        logging.info("HEARTBEAT: STARTING UP")
        cur=self.postgre.cursor()
        QUERY_WORKER = '''SELECT id, status FROM workers_worker'''

        cur.execute(QUERY_WORKER, ())

        workers_db= cur.fetchall()
        self.workers=[x[0] for x in workers_db]
        logging.info("HEARTBEAT: WORKERS ON BD " + str(self.workers))
    
    def broadcast(self):
        logging.info("HEARTBEAT: SENDING BROADCAST")
        if len(self.workers)>0:
            self.producer.send("HEARTBEAT", {'to':'all', 'from':'colector'})
            self.producer.flush()

    def endup(self):
        logging.info("HEARTBEAT: ENDING UP")
        cur=self.postgre.cursor()
        waiting_workers=json.loads(self.redis.get("waiting_workers"))

        workers_del=[x for x in self.workers if x not in waiting_workers]
        logging.info("HEARTBEAT: WORKERS TO DELETE " + str(workers_del))
        for w in workers_del:
            QUERY_WORKER_DEL = '''DELETE FROM workers_worker WHERE id=%s'''
            cur.execute(QUERY_WORKER_DEL, (w,))
            self.postgre.commit()
        
        self.postgre.close()

