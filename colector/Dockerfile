FROM python:3.8-slim-buster

COPY requirements.txt requirements.txt

RUN pip3 install -r requirements.txt

COPY . . 

RUN pytest ./tests/test_colector.py
RUN chmod a+x script.sh

CMD ["./script.sh"]
