from celery import Celery
import logging
from pymongo import MongoClient
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError
import logging
import time
import json
import psycopg2
import re


colector_topics=['INIT','SCAN_REQUEST','FRONTEND','LOG']

app = Celery()
app.config_from_object('celeryconfig')


    
@app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    # Calls test('hello') every 10 seconds.
    sender.add_periodic_task(10.0, testee(), name='add every 10')

@app.task
def testee():
    logging.warning("hello")


@app.task
def main():
    global producer
    global consumer
    global conn
    
    #kafka producer
    producer = KafkaProducer(bootstrap_servers='kafka:9092',
                          security_protocol='SASL_SSL',
                          ssl_cafile='./colector_certs/CARoot.pem',
                          ssl_certfile='./colector_certs/certificate.pem',
                          ssl_keyfile='./colector_certs/key.pem',
                          sasl_mechanism='PLAIN',
                          sasl_plain_username='colector',
                          sasl_plain_password='colector',
                          ssl_check_hostname=False,
                          api_version=(2,7,0),
                          value_serializer=lambda m: json.dumps(m).encode('latin'))

    #kafka consumer
    consumer = KafkaConsumer(bootstrap_servers='kafka:9092',
                          auto_offset_reset='earliest',
                          group_id='colector',
                          security_protocol='SASL_SSL',
                          ssl_cafile='./colector_certs/CARoot.pem',
                          ssl_certfile='./colector_certs/certificate.pem',
                          ssl_keyfile='./colector_certs/key.pem',
                          sasl_mechanism='PLAIN',
                          sasl_plain_username='colector',
                          sasl_plain_password='colector',
                          ssl_check_hostname=False,
                          api_version=(2,7,0),
                          value_deserializer=lambda m: json.loads(m.decode('latin')))
    consumer.subscribe(colector_topics)

    #postgres db
    conn = psycopg2.connect(host="db",database="secureuall",user="frontend", password="abc")
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
            logging.warning("Received a message from frontend")
        elif msg.topic == colector_topics[3]:
            logging.warning("Received logs")
            #TODO Store logs
            #Send notification email
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
        logging.warning(machine)
        cur.execute(QUERY, (machine,))
        
        QUERY_WORKER_MACHINE = '''INSERT INTO machines_machine_workers VALUES(%s,%s)'''
        #If not add to db

        machine_id = cur.fetchone()
        if machine_id is None:
            QUERY = '''INSERT INTO machines_machine(ip, dns, os, risk, \"scanLevel\",location,periodicity, \"nextScan\") VALUES(%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id'''
            if re.fullmatch("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}",machine):
                cur.execute(QUERY, (machine,'null','null', 'null','null','2','W','CURRENT_DATE'))
            else:
                cur.execute(QUERY, ('null', machine,'null', 'null','null','2','W','CURRENT_DATE'))
            machine_id= cur.fetchone()
            conn.commit()

        cur.execute(QUERY_WORKER_MACHINE, (machine_id[0],worker_id,)) 
        conn.commit()
    conn.close()

    #send id
    producer.send(colector_topics[0],key=msg.key, value={'STATUS':'200','WORKER_ID':worker_id})
    producer.flush()