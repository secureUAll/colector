from celery import Celery
import logging
from connections import connect_kafka_consumer, connect_kafka_producer, connect_postgres
from pymongo import MongoClient
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError
import logging
import time
import json
import psycopg2
import re
import smtplib
import ssl


colector_topics=['INIT','SCAN_REQUEST','FRONTEND','LOG']

app = Celery()
app.config_from_object('celeryconfig')


    
@app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    sender.add_periodic_task(60, scan.s())

#get the next machines to be scanned
@app.task
def scan():
    conn= connect_postgres()
    producer=connect_kafka_producer()

    QUERY = '''SELECT id, ip, dns, \"scanLevel\", periodicity  FROM  machines_machine WHERE \"nextScan\" < NOW()'''
    cur = conn.cursor()
    cur.execute(QUERY)

    machines= cur.fetchall()
    for machine in machines:
        QUERY_WORKER = '''SELECT worker_id FROM machines_machineworker WHERE machine_id= %s'''
        
        if machine[4] == 'D':
            QUERY_MACHINE = '''UPDATE  machines_machine SET \"nextScan\" = NOW() + interval \'1 day\'  WHERE id= %s'''
            
        elif machine[4]=='M':
            QUERY_MACHINE = '''UPDATE  machines_machine SET \"nextScan\" = NOW() + interval \'1 month\'  WHERE id= %s'''
        else:
            QUERY_MACHINE = '''UPDATE  machines_machine SET \"nextScan\" = NOW() + interval \'7 days\'  WHERE id= %s'''
        cur.execute(QUERY_MACHINE, (machine[0],))

        conn.commit()
        cur.execute(QUERY_WORKER, (machine[0],))

        workers= cur.fetchall()
        for worker in workers:
            if machine[1] == 'null':
                producer.send(colector_topics[1],key=bytes(worker[0]), value={"MACHINE":machine[2],"SCRAP_LEVEL":machine[3]})
            else: 
                producer.send(colector_topics[1],key=bytes(worker[0]), value={"MACHINE":machine[1],"SCRAP_LEVEL":machine[3]})
    producer.flush()
    conn.close()


@app.task
def main():
    global producer
    global consumer
    global conn
    
    #kafka producer
    producer = connect_kafka_producer()

    #kafka consumer
    consumer = connect_kafka_consumer()
    consumer.subscribe(colector_topics)

    #postgres db
    conn = connect_postgres()
    logging.warning("connected to postgres")
    logging.warning(conn)

    logging.warning(consumer.subscription())
    main_loop()

def main_loop():
 
    logging.warning(consumer.subscription())
    for msg in consumer:
        
        if msg.topic == colector_topics[0]:
            if 'CONFIG' in msg.value:
                #guard configuration on BD and retrive id
                initial_worker(msg)
            
        elif msg.topic == colector_topics[2]:
            if msg.key==b'SCAN':
                scan_machine(msg)
        elif msg.topic == colector_topics[3]:
            logging.warning("Received logs")
            logs(msg)
        else:
            logging.warning("Message topic: "+ msg.topic + " does not exist" )

def initial_worker(msg):
    logging.warning("Received a init message")

    #sql query to insert worker
    QUERY = '''INSERT INTO workers_worker(name,status,failures) VALUES(%s,%s,%s) RETURNING id'''

    # create a new cursor
    cur = conn.cursor()
    cur.execute(QUERY, ("worker","IDLE","0"))

    # get the generated id back
    worker_id = cur.fetchone()[0]
    # commit the changes to the database
    conn.commit()

    for machine in msg.value['CONFIG']['ADDRESS_LIST']:
        #See if machine exists
        QUERY = '''SELECT id FROM  machines_machine WHERE ip = %s'''
        cur.execute(QUERY, (machine,))
        
        QUERY_WORKER_MACHINE = '''INSERT INTO machines_machineworker(machine_id,worker_id) VALUES(%s,%s)'''
        #If not add to db

        machine_id = cur.fetchone()
        if machine_id is None:
            QUERY = '''INSERT INTO machines_machine(ip,dns, \"scanLevel\",periodicity, \"nextScan\") VALUES(%s,%s,%s,%s,%s) RETURNING id'''
            if re.fullmatch("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}",machine):
                cur.execute(QUERY, (machine,'null','2','W','NOW()'))
            else:
                cur.execute(QUERY, ('null', machine,'2','W','NOW()'))
            machine_id= cur.fetchone()
            conn.commit()

        cur.execute(QUERY_WORKER_MACHINE, (machine_id[0],worker_id)) 
        conn.commit()
    conn.close()

    #send id
    producer.send(colector_topics[0],key=msg.key, value={'STATUS':'200','WORKER_ID':worker_id})
    producer.flush()

def scan_machine(msg):
    QUERY = '''SELECT id, ip, dns, \"scanLevel\"  FROM  machines_machine WHERE ip=%s OR dns=%s'''
    
    cur = conn.cursor()
    cur.execute(QUERY,(msg.value['MACHINE'],msg.value['MACHINE']))

    machine= cur.fetchone()

    QUERY_WORKER = '''SELECT worker_id FROM machines_machineworker WHERE machine_id= %s'''
        
    if machine[4] == 'D':
        QUERY_MACHINE = '''UPDATE  machines_machine SET \"nextScan\" = NOW() + interval \'1 day\'  WHERE id= %s'''
            
    elif machine[4]=='M':
        QUERY_MACHINE = '''UPDATE  machines_machine SET \"nextScan\" = NOW() + interval \'1 month\'  WHERE id= %s'''
    else:
        QUERY_MACHINE = '''UPDATE  machines_machine SET \"nextScan\" = NOW() + interval \'7 days\'  WHERE id= %s'''
    cur.execute(QUERY_MACHINE, (machine[0],))

    conn.commit()
    cur.execute(QUERY_WORKER, (machine[0],))

    workers= cur.fetchall()
    for worker in workers:
        if machine[1] == 'null':
            producer.send(colector_topics[1],key=bytes(worker[0]), value={"MACHINE":machine[2],"SCRAP_LEVEL":machine[3]})
        else: 
            producer.send(colector_topics[1],key=bytes(worker[0]), value={"MACHINE":machine[1],"SCRAP_LEVEL":machine[3]})
    producer.flush()
    conn.close()

def logs(msg):
    QUERY = '''SELECT id FROM  machines_machine WHERE ip = %s'''
    #TODO store and process logs
    #send notification email

    

"""
mailserver = smtplib.SMTP('smtp.office365.com',587)
mailserver.ehlo()
mailserver.starttls()
password=input("->")
mailserver.login('margarida.martins@ua.pt', password)
mailserver.sendmail('margarida.martins@ua.pt','margarida.martins@ua.pt','\npython email')
mailserver.quit()
"""