from pymongo import MongoClient
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError
import logging
import time
import json

#logging.basicConfig(level=logging.DEBUG)

time.sleep(10)
logging.warning("Colector started")
#mongo_client = MongoClient("mongodb://localhost:27017/")
#print(mongo_client)


def main():
 
    logging.warning(consumer.subscription())

    for msg in consumer:
        
        if msg.topic == colector_topics[0]:
            logging.warning("Received a init message")

            #guard configuration on BD and retrive id

            #send id
            producer.send(colector_topics[0],key=msg.key, value={'STATUS':'200','WORKER_ID':'1'})

        elif msg.topic == colector_topics[1]:
            logging.warning("Received a scan request message")
        else:
            logging.warning("Message topic: "+ msg.topic + " does not exist" )
        time.sleep(3)

if __name__ == "__main__":

    #topics colector subscribes 
    colector_topics=['INIT','SCAN_REQUEST']

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
                          security_protocol='SASL_SSL',
                          ssl_cafile='./colector_certs/CARoot.pem',
                          ssl_certfile='./colector_certs/certificate.pem',
                          ssl_keyfile='./colector_certs/key.pem',
                          sasl_mechanism='PLAIN',
                          sasl_plain_username='colector',
                          sasl_plain_password='colector',
                          ssl_check_hostname=False,
                          api_version=(2,7,0),
                          value_deserializer=lambda m: json.dumps(m).encode('latin'))
    consumer.subscribe(colector_topics)
    main()