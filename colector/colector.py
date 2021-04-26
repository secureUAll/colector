from pymongo import MongoClient
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError
import logging
import time


#mongo_client = MongoClient("mongodb://localhost:27017/")
#print(mongo_client)

time.sleep(10)
logging.warning("Colector started")

producer = KafkaProducer(bootstrap_servers='kafka:9092',
                          security_protocol='SSL',
                          ssl_cafile='./colector_certs/CARoot.pem',
                          ssl_certfile='./colector_certs/certificate.pem',
                          ssl_keyfile='./colector_certs/key.pem',
                          ssl_check_hostname=False,
                          api_version=(2,7,0))

consumer = KafkaConsumer('test',bootstrap_servers='kafka:9092',
                          security_protocol='SSL',
                          ssl_cafile='./colector_certs/CARoot.pem',
                          ssl_certfile='./colector_certs/certificate.pem',
                          ssl_keyfile='./colector_certs/key.pem',
                          ssl_check_hostname=False,
                          api_version=(2,7,0))

# Write hello world to test topic
producer.send('test', b'Hello World')
producer.flush()
logging.warning(consumer.topics())

for msg in consumer:
    logging.warning("Message"+ str(msg))
    time.sleep(3)
