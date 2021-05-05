from pymongo import MongoClient
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError
import logging  
import os 
import json
import time

#logging.basicConfig(level=logging.DEBUG)
time.sleep(22)
colector_topics=['INIT','SCAN_REQUEST']

#kafka producer
producer = KafkaProducer(bootstrap_servers='kafka:9092',
                          security_protocol='SASL_SSL',
                          ssl_cafile='./colector_certs/CARoot.pem',
                          ssl_certfile='./colector_certs/certificate.pem',
                          ssl_keyfile='./colector_certs/key.pem',
                          sasl_mechanism='PLAIN',
                          sasl_plain_username='worker',
                          sasl_plain_password='worker',
                          ssl_check_hostname=False,
                          api_version=(2,7,0),
                          value_serializer=lambda m: json.dumps(m).encode('latin'))

#kafka consumer
consumer = KafkaConsumer(bootstrap_servers='kafka:9092',
                          auto_offset_reset='earliest',
                          security_protocol='SASL_SSL',
                          ssl_cafile='./colector_certs/CARoot.pem',
                          ssl_certfile='./colector_certs/certificate.pem',
                          ssl_keyfile='./colector_certs/key.pem',
                          sasl_mechanism='PLAIN',
                          sasl_plain_username='worker',
                          sasl_plain_password='worker',
                          ssl_check_hostname=False,
                          api_version=(2,7,0),
                          value_deserializer=lambda m: json.loads(m.decode('latin')))
consumer.subscribe(colector_topics)


logging.warning("worker")
logging.warning(consumer.subscription())


#init message 
random= os.urandom(16)
message={'CONFIG':{'ADDRESS_LIST':['123.4.4.4','123.3.3.3']}}

producer.send(colector_topics[0], key=random , value=message)
producer.flush()

for message in consumer:
    logging.warning(message.topic)
    logging.warning(message.value)
