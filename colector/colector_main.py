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
        logging.info("connected to postgres")
        logging.info(self.conn)       

    #
    # Main Colector loop
    #
    def run(self):
        r=connect_redis()

        logging.info(f"Colector subscribed to: {self.consumer.subscription()}")

        for msg in self.consumer:

            # New Worker is joining
            if msg.topic == self.colector_topics[0]:
                if 'CONFIG' in msg.value:
                    #guard configuration on BD and retrive id
                    self.initial_worker(msg.value,msg.key)

            elif msg.topic == self.colector_topics[1]:
                continue

            # Django is sending a message
            elif msg.topic == self.colector_topics[2]:

                # User requested a scan
                if msg.key==b'SCAN':
                    self.scan_machine(msg)

                # Admin updated workers host list
                elif msg.key == b'UPDATE':
                    self.update_worker(msg)
            
            # Received scan results from worker
            elif msg.topic == self.colector_topics[3]:
                #logging.warning(msg)
                #self.logs(msg)
                self.report(msg)
            
            # Received HeartBeat message
            elif msg.topic == self.colector_topics[4]:
                if msg.value["to"]=="colector":
                    waiting_workers=json.loads(r.get("waiting_workers"))
                    waiting_workers.append(msg.value["from"])
                    r.set("waiting_workers", str(waiting_workers))
                    
            else:
                logging.warning(f"Message topic: {msg.topic} does not exist" )
        logging.info("Closing connection" )
        self.conn.close()

    #
    # Process worker initial message
    #
    def initial_worker(self,value, key):
        logging.info("Received a init message")

        #sql query to insert worker
        QUERY = '''INSERT INTO workers_worker(name,status,failures,created) VALUES(%s,%s,%s,%s) RETURNING id'''

        # create a new cursor
        cur = self.conn.cursor()
        cur.execute(QUERY, ("worker","I","0", "NOW()"))

        # get the generated id back
        worker_id = cur.fetchone()[0]

        logging.info(f"Created worker with id {worker_id}")

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
                logging.info(f"Adding machine {machine} to database")

                QUERY = '''INSERT INTO machines_machine(ip,dns, \"scanLevel\", periodicity, \"nextScan\", active, created, updated) VALUES(%s,%s,'4','W',NOW(), true, NOW(), NOW() ) RETURNING id'''
                if re.fullmatch("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}",machine):
                    cur.execute(QUERY, (machine,''))
                else:
                    cur.execute(QUERY, ('', machine))
                machine_id= cur.fetchone()
                self.conn.commit()

            cur.execute(QUERY_WORKER_MACHINE, (machine_id[0],worker_id)) 
            self.conn.commit()
        cur.close()
        
        #send id
        self.producer.send(self.colector_topics[0],key=key, value={'STATUS':'200','WORKER_ID':worker_id})
        self.producer.flush()

    #
    # Process user scan request
    #
    def scan_machine(self,msg):
        QUERY = '''SELECT id, ip, dns, \"scanLevel\",periodicity  FROM  machines_machine WHERE id=%s'''
        
        cur = self.conn.cursor()
        cur.execute(QUERY,(msg.value['ID'],))

        machine= cur.fetchone()

        logging.info(f"Sending scan request of host {machine[1] if machine[1]!='' else machine[2]}")

        #get workers associated with the host
        QUERY_WORKER = '''SELECT worker_id FROM machines_machineworker WHERE machine_id= %s'''
        
        #update host next scan
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
                logging.info(f"Sending Worker {str(worker[0])} a scanning request of host with dns {machine[2]}")
                self.producer.send(self.colector_topics[1],key=bytes([worker[0]]), value={"MACHINE_ID": machine[0], "MACHINE":machine[2],"SCRAP_LEVEL":machine[3]})
            else:
                logging.info(f"Sending Worker {str(worker[0])} a scanning request of host with dns {machine[1]}") 
                self.producer.send(self.colector_topics[1],key=bytes([worker[0]]), value={"MACHINE_ID": machine[0],"MACHINE":machine[1],"SCRAP_LEVEL":machine[3]})
        self.producer.flush()
        cur.close()


    #
    # Update Worker host list
    #
    def update_worker(self,msg):
        logging.info("Sending worker updated host list")
        
        worker_machine_list= []
        worker_id = msg.value["ID"]

        QUERY_WORKER = '''SELECT mm.ip, mm.dns FROM machines_machineworker as mw INNER JOIN  machines_machine as mm ON mw.machine_id = mm.id WHERE mw.worker_id=%s'''
        cur = self.conn.cursor()
        cur.execute(QUERY_WORKER, (worker_id,))

        machines=cur.fetchall()

        logging.info(f"New machine list:\n{machines}")
        for machine in machines:
            if machine[0]:
                worker_machine_list.append(machine[0])
            else:
                worker_machine_list.append(machine[1])

        cur.close()
        self.producer.send(self.colector_topics[5], key=bytes([worker_id]), value={"ADDRESS_LIST": worker_machine_list})
        self.producer.flush()


    #
    # Save logs to db
    #
    def logs(self,msg):
        logging.warning("ENTROU NOS LOGS")
        QUERY = '''INSERT INTO machines_log (date, log, machine_id, worker_id) VALUES(%s, %s,%s , %s)'''
        cur = self.conn.cursor()

        # parameters
        dt = datetime.now(timezone.utc)
        log=json.dumps(msg.value["RESULTS"]).encode('latin')
        worker_id=int.from_bytes(msg.key,"big")
        machine_id=msg.value["MACHINE_ID"]

        # insert into log's table
        cur.execute(QUERY, (dt, log, machine_id, worker_id))
        self.conn.commit()
        cur.close()

    
    #
    # Generate report based on logs found
    #
    def report(self,msg):

        logging.info("Generating report")
        # Generate report and get notification info
        report=Report(self.conn)
        email_info =report.report(msg)

        # With the report info sending user notification
        from celery_worker import send_email
        logging.info("Sending email")
        send_email.delay(email_info)
