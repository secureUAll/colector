from celery import Task
from connections import connect_kafka_producer,connect_kafka_consumer,  connect_postgres, connect_redis
import logging
import json
import re
from datetime import date

class Main(Task):

    def __init__(self):
        colector_topics=['INIT','SCAN_REQUEST','FRONTEND','LOG', 'HEARTBEAT', 'UPDATE']
        #kafka producer
        producer = connect_kafka_producer()

        #kafka consumer
        consumer = connect_kafka_consumer()
        consumer.subscribe(colector_topics)

        #postgres db
        conn = connect_postgres()
        logging.warning("connected to postgres")
        logging.warning(conn)

        producer.send(colector_topics[0],value={"init consumer":"sss"})
        

    def run(self):
        r=connect_redis()
        logging.warning(self.consumer.subscription())
        for msg in self.consumer:
            if msg.topic == self.colector_topics[0]:
                if 'CONFIG' in msg.value:
                    #guard configuration on BD and retrive id
                    self.initial_worker(msg.value,msg.key)
            elif msg.topic == self.colector_topics[1]:
                continue
            elif msg.topic == self.colector_topics[2]:
                if msg.key==b'SCAN':
                    self.scan_machine(msg)
                elif msg.key == b'UPDATE':
                    self.update_worker(msg)
            elif msg.topic == self.colector_topics[3]:
                logging.warning(msg)
                #logs(msg)
                #report(msg)
            elif msg.topic == self.colector_topics[4]:
                if msg.value["to"]=="colector":
                    waiting_workers=json.loads(r.get("waiting_workers"))
                    waiting_workers.append(msg.value["from"])
                    r.set("waiting_workers", str(waiting_workers))
                    
            else:
                logging.warning("Message topic: "+ msg.topic + " does not exist" )
        logging.warning("Closing connection" )
        self.conn.close()

    def initial_worker(self,value, key):
        logging.warning("Received a init message")

        #sql query to insert worker
        QUERY = '''INSERT INTO workers_worker(name,status,failures,created) VALUES(%s,%s,%s,%s) RETURNING id'''

        # create a new cursor
        cur = self.conn.cursor()
        cur.execute(QUERY, ("worker","I","0", str(date.today())))

        # get the generated id back
        worker_id = cur.fetchone()[0]
        # commit the changes to the database
        self.conn.commit()

        for machine in value['CONFIG']['ADDRESS_LIST']:
            #See if machine exists
            QUERY = '''SELECT id FROM  machines_machine WHERE ip = %s or dns= %s'''
            self.cur.execute(QUERY, (machine,machine))
            
            QUERY_WORKER_MACHINE = '''INSERT INTO machines_machineworker(machine_id,worker_id) VALUES(%s,%s)'''
            #If not add to db

            machine_id = cur.fetchone()
            if machine_id is None:
                QUERY = '''INSERT INTO machines_machine(ip,dns, \"scanLevel\",periodicity, \"nextScan\") VALUES(%s,%s,%s,%s,%s) RETURNING id'''
                if re.fullmatch("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}",machine):
                    cur.execute(QUERY, (machine,'','2','W','NOW()'))
                else:
                    cur.execute(QUERY, ('', machine,'2','W','NOW()'))
                machine_id= cur.fetchone()
                self.conn.commit()

            cur.execute(QUERY_WORKER_MACHINE, (machine_id[0],worker_id)) 
            self.conn.commit()
        cur.close()
        
        #send id
        self.producer.send(self.colector_topics[0],key=key, value={'STATUS':'200','WORKER_ID':worker_id})
        self.producer.flush()

        

    