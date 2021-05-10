CREATE TABLE machines_machine(
    id SERIAL PRIMARY KEY,
    ip VARCHAR(15),
    dns VARCHAR(256),
    scanLevel VARCHAR(3),
    periodicity VARCHAR(3),
    nextScan TIMESTAMP
);

CREATE TABLE workers_worker(
    id SERIAL PRIMARY KEY,
    name VARCHAR(265),
    status VARCHAR(3),
    failures int,
    created TIMESTAMP
);

CREATE TABLE machines_log(
    date TIMESTAMP,
    path VARCHAR(256),
    machine_id int,
    worker_id int,
    PRIMARY KEY (date, machine_id, worker_id),
    CONSTRAINT fk_machines_machine FOREIGN KEY(machine_id) REFERENCES machines_machine(id),
    CONSTRAINT fk_workers_worker FOREIGN KEY(worker_id) REFERENCES workers_worker(id)
);

CREATE TABLE machines_machineworker(
    machine_id int,
    worker_id int,
    PRIMARY KEY (machine_id, worker_id),
    CONSTRAINT fk_machines_machine_worker FOREIGN KEY(machine_id) REFERENCES machines_machine(id),
    CONSTRAINT fk_workers_worker_eorker FOREIGN KEY(worker_id) REFERENCES workers_worker(id)
);

INSERT INTO machines_machine (id, ip) VALUES (14, '0.0.0.0');
--INSERT INTO workers_worker(name, status, failures, created) VALUES 
