import time
from datetime import datetime, timezone
from connections import connect_kafka_producer,connect_kafka_consumer,  connect_postgres, connect_redis
import logging
import json
import re
from report import Report

class Main():
    def __init__(self):
        self.colector_topics=['INIT','SCAN_REQUEST','FRONTEND','LOG', 'HEARTBEAT', 'UPDATE']
        #kafka producer
        self.producer = connect_kafka_producer()

        #kafka consumer
        self.consumer = connect_kafka_consumer()
        self.consumer.subscribe(self.colector_topics)

        #postgres db
        self.conn = connect_postgres()
        logging.warning("connected to postgres")
        logging.warning(self.conn)       

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
                #logging.warning(msg)
                #self.logs(msg)
                self.report(msg)
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
        cur.execute(QUERY, ("worker","I","0", "NOW()"))

        # get the generated id back
        worker_id = cur.fetchone()[0]
        # commit the changes to the database
        self.conn.commit()

        for machine in value['CONFIG']['ADDRESS_LIST']:
            #See if machine exists
            QUERY = '''SELECT id FROM  machines_machine WHERE ip = %s or dns= %s'''
            cur.execute(QUERY, (machine,machine))
            
            QUERY_WORKER_MACHINE = '''INSERT INTO machines_machineworker(machine_id,worker_id) VALUES(%s,%s)'''
            #If not add to db

            machine_id = cur.fetchone()
            if machine_id is None:
                QUERY = '''INSERT INTO machines_machine(ip,dns, \"scanLevel\", periodicity, \"nextScan\") VALUES(%s,%s,%s,%s,%s) RETURNING id'''
                if re.fullmatch("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}",machine):
                    cur.execute(QUERY, (machine,'','2','W','NOW()'))
                else:
                    cur.execute(QUERY, ('', machine, '2','W', 'NOW()'))
                machine_id= cur.fetchone()
                self.conn.commit()

            cur.execute(QUERY_WORKER_MACHINE, (machine_id[0],worker_id)) 
            self.conn.commit()
        cur.close()
        
        #send id
        self.producer.send(self.colector_topics[0],key=key, value={'STATUS':'200','WORKER_ID':worker_id})
        self.producer.flush()

    def scan_machine(self,msg):
        QUERY = '''SELECT id, ip, dns, \"scanLevel\",periodicity  FROM  machines_machine WHERE ip=%s OR dns=%s'''
        
        cur = self.conn.cursor()
        cur.execute(QUERY,(msg.value['MACHINE'],msg.value['MACHINE']))


        machine= cur.fetchone()
        logging.warning( machine  )
        QUERY_WORKER = '''SELECT worker_id FROM machines_machineworker WHERE machine_id= %s'''
            
        if machine[4] == 'D':
            QUERY_MACHINE = '''UPDATE  machines_machine SET \"nextScan\" = NOW() + interval \'1 day\'  WHERE id= %s'''
                
        elif machine[4]=='M':
            QUERY_MACHINE = '''UPDATE  machines_machine SET \"nextScan\" = NOW() + interval \'1 month\'  WHERE id= %s'''
        else:
            QUERY_MACHINE = '''UPDATE  machines_machine SET \"nextScan\" = NOW() + interval \'7 days\'  WHERE id= %s'''
        cur.execute(QUERY_MACHINE, (machine[0],))

        self.conn.commit()
        cur.execute(QUERY_WORKER, (machine[0],))

        workers= cur.fetchall()
        for worker in workers:
            if machine[1] == '':
                self.producer.send(self.colector_topics[1],key=bytes([worker[0]]), value={"MACHINE_ID": machine[0], "MACHINE":machine[2],"SCRAP_LEVEL":machine[3]})
            else: 
                self.producer.send(self.colector_topics[1],key=bytes([worker[0]]), value={"MACHINE_ID": machine[0],"MACHINE":machine[1],"SCRAP_LEVEL":machine[3]})
        self.producer.flush()
        cur.close()

    def update_worker(self,msg):
        logging.warning("UPDATING WORKER")
        
        worker_machine_list= []
        worker_id = msg.value["ID"]

        QUERY_WORKER = '''SELECT mm.ip, mm.dns FROM machines_machineworker as mw INNER JOIN  machines_machine as mm ON mw.machine_id = mm.id WHERE mw.worker_id=%s'''
        cur = self.conn.cursor()
        cur.execute(QUERY_WORKER, (worker_id,))

        machines=cur.fetchall()
        for machine in machines:
            if machine[0]:
                worker_machine_list.append(machine[0])
            else:
                worker_machine_list.append(machine[1])
        cur.close()
        self.producer.send(self.colector_topics[5], key=bytes(worker_id), value={"ADDRESS_LIST": worker_machine_list})
        self.producer.flush()

    def logs(self,msg):
        logging.warning("ENTROU NOS LOGS")
        QUERY = '''INSERT INTO machines_log (date, path, machine_id, worker_id) VALUES(%s, %s, (SELECT id FROM machines_machine WHERE ip = %s or dns=%s LIMIT 1), %s)'''
        cur = self.conn.cursor()

        # parameters
        dt = datetime.now(timezone.utc)
        path="logs/"+str(round(time.time() * 1000))
        worker_id=int.from_bytes(msg.key,"big")
        machine_ip=msg.value["MACHINE"]

        # insert into log's table
        cur.execute(QUERY, (dt, path, machine_ip,machine_ip, worker_id))
        self.conn.commit()
        cur.close()
        
        # guardar os logs num ficheiro
        f=open(path, "wb")
        f.write(json.dumps(msg.value["RESULTS"]).encode('latin'))

        """logging.warning("ENTROU NOS LOGS, CONECTOU À BD, GUARDOU NA TABELA, GUARDOU NO PATH, AGORA VAMOS VER O QUE FICOU GUARDADO")
        f=open(path, "rb")
        txt=f.read()
        """
    
    def report(self,msg):
        report=Report(self.conn)
        email_info =report.report(msg)
        #from celery_worker import send_email
        #send_email(msg)
