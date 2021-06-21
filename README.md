# Colector

The colector is responsible jo assign scanning jobs to the workers and saving the data which will be displayed in our web platform. 
The colector-worker communication is done via kafka.

The Colector runs two periodic tasks: **heartbeat** and **scan**. These tasks were implemented using Celery.

**Heartbeat** task is used in order to perform health checks on the workers.

**Scan** task will get all host which have to be scaned (using nextScan property) and send scanning request messages to the workers.
