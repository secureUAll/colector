FROM wurstmeister/kafka

COPY wait-for-it.sh /wait-for-it.sh

RUN chmod +x /wait-for-it.sh

CMD ["/wait-for-it.sh", "zookeper:2181", "--", "start-kafka.sh"]
