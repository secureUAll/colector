from notification_sender import NotificationSender
from Heartbeat import Heartbeat
from celery import Celery
import logging
import os
import sys
from connections import connect_kafka_consumer, connect_kafka_producer, connect_postgres, connect_redis

import logging
import time


producer=None
consumer=None
conn=None

colector_topics=['INIT','SCAN_REQUEST','FRONTEND','LOG', 'HEARTBEAT', 'UPDATE']
sys.path.append(os.getcwd())
app = Celery()
app.config_from_object('celeryconfig')
    
@app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    sender.add_periodic_task(60*5, heartbeat.s())
    sender.add_periodic_task(60, scan.s())

@app.task()
def main():
    logging.info("Starting Colector")

    from colector_main import Main
    m=Main()
    m.run()

#
# Task to get the next hosts to be scanned
#
@app.task
def scan():
    logging.info("Starting Periodic scanning task")

    conn= connect_postgres()
    producer=connect_kafka_producer()

    # get hosts to be scanned
    QUERY = '''SELECT id, ip, dns, \"scanLevel\", periodicity  FROM  machines_machine WHERE \"nextScan\" <= NOW() and active=true'''

    cur = conn.cursor()
    cur.execute(QUERY)

    machines= cur.fetchall()
    for machine in machines:

        #get workers associated with the host
        QUERY_WORKER = '''SELECT worker_id FROM machines_machineworker WHERE machine_id= %s'''
        QUERY_WORKER_UPDATE = '''UPDATE workers_worker SET status=\'A\' WHERE id= %s'''
        
        #update host next scan
        if machine[4] == 'D':
            QUERY_MACHINE = '''UPDATE  machines_machine SET \"nextScan\" = NOW() + interval \'1 day\'  WHERE id= %s'''
            
        elif machine[4]=='M':
            QUERY_MACHINE = '''UPDATE  machines_machine SET \"nextScan\"= NOW() + interval \'1 month\'  WHERE id= %s'''
        else:
            QUERY_MACHINE = '''UPDATE  machines_machine SET \"nextScan\" = NOW() + interval \'7 days\'  WHERE id= %s'''
        cur.execute(QUERY_MACHINE, (machine[0],))

        conn.commit()
        cur.execute(QUERY_WORKER, (machine[0],))

        workers= cur.fetchall()
        for worker in workers:

            cur.execute(QUERY_WORKER_UPDATE, (worker[0],))
            conn.commit()
            if machine[1] == '':
                logging.info(f"Sending Worker {str(worker[0])} a scanning request of host with dns {machine[2]}")
                producer.send(colector_topics[1],key=bytes([worker[0]]), value={"MACHINE_ID": machine[0],"MACHINE":machine[2],"SCRAP_LEVEL":machine[3]})
            else:
                logging.info(f"Sending Worker {str(worker[0])} a scanning request of host with ip {machine[1]}") 
                producer.send(colector_topics[1],key=bytes([worker[0]]), value={"MACHINE_ID": machine[0],"MACHINE":machine[1],"SCRAP_LEVEL":machine[3]})

    producer.flush()
    conn.close()

@app.task
def heartbeat():

    logging.info(f"Starting Heartbeat")
    hb = Heartbeat()
    hb.startup()
    hb.broadcast()

    #ttl
    time.sleep(30)

    hb.endup()

@app.task()
def send_email(info):

    logging.info(f"Starting Notification")

    ns = NotificationSender(info)
    ns.run()



