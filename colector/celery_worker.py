from celery import Celery
import logging
from connections import connect_kafka_consumer, connect_kafka_producer, connect_postgres, connect_redis
from datetime import date
from pymongo import MongoClient
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError
from datetime import datetime, timezone
import logging
import time
import json
import psycopg2
import re
import smtplib
import ssl

producer=None
consumer=None
conn=None

colector_topics=['INIT','SCAN_REQUEST','FRONTEND','LOG','UPDATE', 'HEARTBEAT']

app = Celery()
app.config_from_object('celeryconfig')
    
@app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    sender.add_periodic_task(10, heartbeat.s()) # TODO: alterar para 300
    sender.add_periodic_task(6000, scan.s())

#get the next machines to be scanned
@app.task
def scan():
    conn= connect_postgres()
    producer=connect_kafka_producer()


    QUERY = '''SELECT id, ip, dns, \"scanLevel\", periodicity  FROM  machines_machine WHERE \"nextScan\" <= NOW()'''

    cur = conn.cursor()
    cur.execute(QUERY)

    machines= cur.fetchall()
    for machine in machines:
        QUERY_WORKER = '''SELECT worker_id FROM machines_machineworker WHERE machine_id= %s'''
        QUERY_WORKER_UPDATE = '''UPDATE workers_worker SET status=\'A\' WHERE id= %s'''
        
        if machine[4] == 'D':
            QUERY_MACHINE = '''UPDATE  machines_machine SET \"nextScan\" = NOW() + interval \'1 day\'  WHERE id= %s'''
            
        elif machine[4]=='M':
            QUERY_MACHINE = '''UPDATE  machines_machine SET \"nextScan\"= NOW() + interval \'1 month\'  WHERE id= %s'''
        else:
            QUERY_MACHINE = '''UPDATE  machines_machine SET \"nextScan\" = NOW() + interval \'7 days\'  WHERE id= %s'''
        cur.execute(QUERY_MACHINE, (machine[0],))

        conn.commit()
        cur.execute(QUERY_WORKER, (machine[0],))

        workers= cur.fetchall()
        for worker in workers:
            logging.warning(bytes([worker[0]]))
            cur.execute(QUERY_WORKER_UPDATE, (worker[0],))
            conn.commit()
            if machine[1] == 'null':
                producer.send(colector_topics[1],key=bytes([worker[0]]), value={"MACHINE":machine[2],"SCRAP_LEVEL":machine[3]})
            else: 
                producer.send(colector_topics[1],key=bytes([worker[0]]), value={"MACHINE":machine[1],"SCRAP_LEVEL":machine[3]})

    producer.flush()
    conn.close()

@app.task
def heartbeat():
    conn= connect_postgres()
    producer=connect_kafka_producer()
    cur = conn.cursor()
    r=connect_redis()
    r.set("waiting_workers", str([]))

    QUERY_WORKER = '''SELECT id, status FROM workers_worker'''

    cur.execute(QUERY_WORKER, ())

    workers= cur.fetchall()
    workers_all=[x[0] for x in workers]

    if len(workers)>0:
        producer.send(colector_topics[4], {'to':'all', 'from':'colector'})
        producer.flush()
    
    time.sleep(3) # TODO: alterar para 60

    waiting_workers=json.loads(r.get("waiting_workers"))

    workers_del=[x for x in workers_all if x not in waiting_workers]
    for w in workers_del:
        QUERY_WORKER_DEL = '''DELETE FROM workers_worker WHERE id=%s'''
        cur.execute(QUERY_WORKER_DEL, (w,))
        conn.commit()
        
    print("Workers alive: "+str(waiting_workers))
    conn.close()

@app.task
def main():
    global producer
    global consumer
    global conn
    global workers_respond

    # temp workers
    workers_respond=[]
    
    #kafka producer
    producer = connect_kafka_producer()

    #kafka consumer
    consumer = connect_kafka_consumer()
    consumer.subscribe(colector_topics)

    #postgres db
    conn = connect_postgres()
    logging.warning("connected to postgres")
    logging.warning(conn)

    producer.send(colector_topics[0],value={"init consumer":"sss"})
    main_loop()

def main_loop():
    r=connect_redis()
    logging.warning(consumer.subscription())
    for msg in consumer:
        if msg.topic == colector_topics[0]:
            if 'CONFIG' in msg.value:
                #guard configuration on BD and retrive id
                initial_worker(msg.value,msg.key)
        elif msg.topic == colector_topics[1]:
            continue
        elif msg.topic == colector_topics[2]:
            if msg.key==b'SCAN':
                scan_machine(msg)
            elif msg.key == b'UPDATE':
                update_worker(msg)
        elif msg.topic == colector_topics[3]:
            logging.warning(msg)
            logs(msg)
            report(msg)
        elif msg.topic == colector_topics[4]:
            if msg.value["to"]=="colector":
                waiting_workers=json.loads(r.get("waiting_workers"))
                waiting_workers.append(msg.value["from"])
                r.set("waiting_workers", str(waiting_workers))
                
        else:
            logging.warning("Message topic: "+ msg.topic + " does not exist" )
    logging.warning("Closing connection" )
    conn.close()

def initial_worker(value,key):
    logging.warning("Received a init message")

    #sql query to insert worker
    QUERY = '''INSERT INTO workers_worker(name,status,failures,created) VALUES(%s,%s,%s,%s) RETURNING id'''

    # create a new cursor
    cur = conn.cursor()
    cur.execute(QUERY, ("worker","I","0", str(date.today())))

    # get the generated id back
    worker_id = cur.fetchone()[0]
    # commit the changes to the database
    conn.commit()

    for machine in value['CONFIG']['ADDRESS_LIST']:
        #See if machine exists
        QUERY = '''SELECT id FROM  machines_machine WHERE ip = %s or dns= %s'''
        cur.execute(QUERY, (machine,machine))
        
        QUERY_WORKER_MACHINE = '''INSERT INTO machines_machineworker(machine_id,worker_id) VALUES(%s,%s)'''
        #If not add to db

        machine_id = cur.fetchone()
        if machine_id is None:
            QUERY = '''INSERT INTO machines_machine(ip,dns, \"scanLevel\",periodicity, \"nextScan\") VALUES(%s,%s,%s,%s,%s) RETURNING id'''
            if re.fullmatch("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}",machine):
                cur.execute(QUERY, (machine,'','2','W','NOW()'))
            else:
                cur.execute(QUERY, ('', machine,'2','W','NOW()'))
            machine_id= cur.fetchone()
            conn.commit()

        cur.execute(QUERY_WORKER_MACHINE, (machine_id[0],worker_id)) 
        conn.commit()
    cur.close()
    
    #send id
    producer.send(colector_topics[0],key=key, value={'STATUS':'200','WORKER_ID':worker_id})
    producer.flush()

def scan_machine(msg):
    QUERY = '''SELECT id, ip, dns, \"scanLevel\",periodicity  FROM  machines_machine WHERE ip=%s OR dns=%s'''
    
    cur = conn.cursor()
    cur.execute(QUERY,(msg.value['MACHINE'],msg.value['MACHINE']))


    machine= cur.fetchone()
    logging.warning( machine  )
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
        if machine[1] == '':
            producer.send(colector_topics[1],key=bytes([worker[0]]), value={"MACHINE":machine[2],"SCRAP_LEVEL":machine[3]})
        else: 
            producer.send(colector_topics[1],key=bytes([worker[0]]), value={"MACHINE":machine[1],"SCRAP_LEVEL":machine[3]})
    producer.flush()
    cur.close()

def update_worker(msg):
    logging.warning("UPDATING WORKER")
    
    worker_machine_list= []
    worker_id = msg.value["ID"]

    QUERY_WORKER = '''SELECT mm.ip, mm.dns FROM machines_machineworker as mw INNER JOIN  machines_machine as mm ON mw.machine_id = mm.id WHERE mw.worker_id=%s'''
    cur = conn.cursor()
    cur.execute(QUERY_WORKER, (worker_id,))

    machines=cur.fetchall()
    for machine in machines:
        if machine[0]:
            worker_machine_list.append(machine[0])
        else:
            worker_machine_list.append(machine[1])
    cur.close()
    producer.send(colector_topics[4], key=bytes(worker_id), value={"ADDRESS_LIST": worker_machine_list})
    producer.flush()


def logs(msg):
    logging.warning("ENTROU NOS LOGS")
    QUERY = '''INSERT INTO machines_log (date, path, machine_id, worker_id) VALUES(%s, %s, (SELECT id FROM machines_machine WHERE ip = %s LIMIT 1), %s)'''
    cur = conn.cursor()

    # parameters
    dt = datetime.now(timezone.utc)
    path="logs/"+str(round(time.time() * 1000))
    worker_id=int.from_bytes(msg.key,"big")
    machine_ip=msg.value["MACHINE"]

    # insert into log's table
    cur.execute(QUERY, (dt, path, machine_ip, worker_id))
    conn.commit()
    cur.close()
    
    # guardar os logs num ficheiro
    f=open(path, "wb")
    f.write(json.dumps(msg.value["RESULTS"]).encode('latin'))

    """logging.warning("ENTROU NOS LOGS, CONECTOU À BD, GUARDOU NA TABELA, GUARDOU NO PATH, AGORA VAMOS VER O QUE FICOU GUARDADO")
    f=open(path, "rb")
    txt=f.read()
    """

def send_email(msg):
    QUERY_USER_EMAILS= "select \"notificationEmail\"  from machines_subscription ms, machines_machine mm where mm.id=ms.machine_id AND (mm.dns=%s OR mm.ip=%s) "

    cur = conn.cursor()
    cur.execute(QUERY_USER_EMAILS, (msg.value["MACHINE"],msg.value["MACHINE"]))
    emails= cur.fetchall()
    for email in emails:
        mailserver = smtplib.SMTP('smtp.office365.com',587)
        mailserver.ehlo()
        mailserver.starttls()
        password=input("->")
        mailserver.login('margarida.martins@ua.pt', password)
        mailserver.sendmail('margarida.martins@ua.pt',email[0],'\n')
        mailserver.quit()
    cur.close()

def report(msg):
    #TODO report 
    send_email(msg)



