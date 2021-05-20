from pymongo import MongoClient
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError
import os 
import json
import logging
import time

import subprocess
import argparse
import json
import xmltodict

def convert_to_json(output_file):

    f = open(output_file)
    xml_content = f.read()
    f.close()

    #write_file = open("out_json.json", "w")
    #write_file.write(json.dumps(xmltodict.parse(xml_content), indent=4, sort_keys=True))
    return json.dumps(xmltodict.parse(xml_content), indent=4, sort_keys=True)



#time.sleep(30)
time.sleep(22)
colector_topics=['INIT','SCAN_REQUEST','LOG','HEARTBEAT']

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
                          value_deserializer=lambda m: json.loads(m.decode('latin')),
                          fetch_max_wait_ms=0)

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
    logging.critical("WORKER LOG" + str(WORKER_ID))
    logging.critical(message.value)
    # initial message response to save WORKER_ID
    if message.topic == "INIT":
        # Get ID
        if message.key == random and "WORKER_ID" in message.value:
            logging.warning(message.value)
            WORKER_ID = message.value['WORKER_ID']

    elif message.topic== colector_topics[1]:
        logging.warning(int.from_bytes(message.key,"big"))
        logging.warning(WORKER_ID)
        if int.from_bytes(message.key,"big") == WORKER_ID:
            logging.warning(message.value)
            # get machine to scan
            machine = message.value["MACHINE"]

            # default scrapping value
            if message.value["SCRAP_LEVEL"] == '2':
                # pull image from registry
                os.system("docker pull localhost/vulscan:latest")
                # runn image
                os.system("docker  run --user \"$(id -u):$(id -g)\" -v `pwd`:`pwd` -w `pwd` -i -t localhost/vulscan:latest -sV --script=vulscan/vulscan.nse " + machine + " -oX out.xml")

                #output_json = convert_to_json("out.xml")
                output_json="{}"

            elif message.value["SCRAP_LEVEL"] == '3':
                continue
            elif message.value["SCRAP_LEVEL"] == '4':
                continue
            
            logging.warning("vai mandar")
            producer.send(colector_topics[2], key=bytes(WORKER_ID), value=output_json)
            producer.flush()
    elif message.topic==colector_topics[3]:
        if message.value["from"]=="colector":
            print("VAI ENVIAAAR")
            producer.send(colector_topics[3], value={'from':WORKER_ID, 'to':"colector"})
            producer.flush()
    
#logging.warning(message.topic)
#logging.warning(message.value)


    


