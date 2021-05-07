from pymongo import MongoClient
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError
import os 
import json
import logging
import time


#time.sleep(30)
time.sleep(22)
colector_topics=['INIT','SCAN_REQUEST','FRONTEND','LOG']

WORKER_ID = 0

#logging.basicConfig(level=logging.DEBUG)

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
random = os.urandom(16)

# Read file with default domains
domains = []
with open("domains.txt", "r") as f:
    # by line
    for line in f:
        # add domain to list
        line = line.strip('\n')
        domains.append(line)

# message with domains
message = {'CONFIG':{'ADDRESS_LIST':domains}}

# Send address list
producer.send(colector_topics[0], key=random , value=message)
producer.flush()

for message in consumer:

    logging.warning("WORKER ")
    logging.warning(message.topic)
    logging.warning(message.value)

    if message.topic == "INIT":
        continue
        # Get ID
        #print(message)
        #if message.key == random:
            #WORKER_ID = message.value['WORKER_ID']

    else:
        if message.key == WORKER_ID:
            machine = message.value["MACHINE"]
            if message.value["SCRAP_LEVEL"] == 2:
                continue
            elif message.value["SCRAP_LEVEL"] == 3:
                continue
            elif message.value["SCRAP_LEVEL"] == 4:
                continue
            
            producer.send(colector_topics[1], key=WORKER_ID, value=message)
            producer.flush()
    
#logging.warning(message.topic)
#logging.warning(message.value)

    


