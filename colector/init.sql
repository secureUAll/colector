CREATE DATABASE secureuall;

USE secureuall;

CREATE TABLE machines_machine(
    id int,
    ip VARCHAR(15),
    dns VARCHAR(256),
    scanLevel VARCHAR(3),
    periodicity VARCHAR(3),
    nextScan TIMESTAMP,
    PRIMARY KEY(id)
);

INSERT INTO machines_machine (id, ip) VALUES (14, '0.0.0.0');

CREATE TABLE machines_log(
    date TIMESTAMP,
    path VARCHAR(256),
    machine_id int FOREIGN KEY REFERENCES machines_machine(id),
    worker_id VARCHAR(265) FOREIGN KEY REFERENCES workers_worker(name),
    PRIMARY KEY (date, machine_id, worker_id)
);

CREATE TABLE workers_worker(
    name VARCHAR(265),
    status VARCHAR(3),
    failures int,
    created TIMESTAMP,
    PRIMARY KEY (name)
);

CREATE TABLE machines_machineworker(
    machine_id int FOREIGN KEY REFERENCES machines_machine(id), 
    worker_id VARCHAR(265) FOREIGN KEY REFERENCES workers_worker(name),
    PRIMARY KEY (machine_id, worker_id)
);