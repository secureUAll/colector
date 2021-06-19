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
        workers_update=[x for x in self.workers if x[1]=="D" and x in waiting_workers]

        logging.info("HEARTBEAT: WORKERS TO SET DOWN " + str(workers_del))
        for w in workers_del:
            QUERY_WORKER_DEL = '''update workers_worker set status='D' where  id=%s'''
            cur.execute(QUERY_WORKER_DEL, (w,))
            self.postgre.commit()

        logging.info("HEARTBEAT: WORKERS TO BE REVIVED " + str(workers_update))
        for w in workers_update:
            QUERY_WORKER_UP = '''update workers_worker set status='A' where  id=%s'''
            cur.execute(QUERY_WORKER_UP, (w,))
            self.postgre.commit()
        
        self.postgre.close()

