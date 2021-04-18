from flask import Flask
from kafka import KafkaProducer, KafkaConsumer

app=Flask(__name__)

@app.route('/produce/<mensagem>')
def produce(mensagem):
	producer = KafkaProducer(bootstrap_servers='localhost:9092')
	producer.send('foobar', mensagem.encode("utf-8"))
	return "Enviada: "+mensagem

@app.route('/consume')
def consume():
	consumer = KafkaConsumer(bootstrap_servers='localhost:9092')
	consumer.subscribe(['foobar'])
	l=""
	for msg in consumer:
		print(msg)
		l+=str(msg)+"<br>"
		break
	
	return l

if __name__=='__main__':
	app.run()
