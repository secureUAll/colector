from pymongo import MongoClient
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError
import logging
import time
logging.basicConfig(level=logging.DEBUG)

#mongo_client = MongoClient("mongodb://localhost:27017/")
#print(mongo_client)



time.sleep(60)

producer = KafkaProducer(bootstrap_servers='kafka:9092',
                          security_protocol='SSL',
                          ssl_cafile='./colector_certs/CARoot.pem',
                          ssl_certfile='./colector_certs/certificate.pem',
                          ssl_keyfile='./colector_certs/key.pem',
                          api_version=(2,7,0))

# Write hello world to test topic
producer.send("test", b'Hello World')
producer.flush()

consumer = KafkaConsumer('test',bootstrap_servers='kafka:9092',
                          security_protocol='SSL',
                          ssl_cafile='./colector_certs/CARoot.pem',
                          ssl_certfile='./colector_certs/certificate.pem',
                          ssl_keyfile='./colector_certs/key.pem',
                          api_version=(2,7,0))

for msg in consumer:
    print(msg)