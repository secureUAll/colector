from kafka import KafkaConsumer, KafkaProducer
import json
import psycopg2
import redis

#
# Creating Kafka Producer
#
def connect_kafka_producer():
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
    
    return producer

#
# Creating Kafka Consumer
#
def connect_kafka_consumer():
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
    
    return consumer

#
# Creating Postgres Connection
#
def connect_postgres():
    conn=psycopg2.connect(host="db",database="secureuall",user="frontend", password="abc")
    return conn

#
# Creating Redis Connection
#
def connect_redis():
    r=redis.Redis(host='shared_mem', port=6379, db=0)
    return r

