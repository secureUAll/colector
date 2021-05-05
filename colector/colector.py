from pymongo import MongoClient
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError
import logging
import time
import json
import psycopg2

#logging.basicConfig(level=logging.DEBUG)

time.sleep(20)
logging.warning("Colector started")
#mongo_client = MongoClient("mongodb://localhost:27017/")
#print(mongo_client)


#https://www.postgresqltutorial.com/postgresql-python
#docker exec -it docker_db_1 bash

def main():
 
    logging.warning(consumer.subscription())
    for msg in consumer:
        
        if msg.topic == colector_topics[0]:
            if 'CONFIG' in msg.value:
                #guard configuration on BD and retrive id
                initial_worker(msg)
            
        elif msg.topic == colector_topics[1]:
            logging.warning("Received a scan request message")
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
            QUERY = '''INSERT INTO machines_machine(ip, dns, os, risk, scanlevel,location) VALUES(%s,%s,%s,%s,%s,%s) RETURNING id'''
            cur.execute(QUERY, (machine,'null','null', 'null','null','2')) #TODO Check regex
            machine_id= cur.fetchone()
            conn.commit()

        cur.execute(QUERY_WORKER_MACHINE, (machine_id[0],worker_id,)) 
        conn.commit()
    conn.close()

    #send id
    producer.send(colector_topics[0],key=msg.key, value={'STATUS':'200','WORKER_ID':worker_id})
    producer.flush()

if __name__ == "__main__":

    #topics colector subscribes 
    colector_topics=['INIT','SCAN_REQUEST','USER_REQUEST','LOG']

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
    main()


