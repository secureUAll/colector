-- public.auth_group definition

-- Drop table

-- DROP TABLE public.auth_group;

CREATE TABLE public.auth_group (
	id serial NOT NULL,
	name varchar(150) NOT NULL,
	CONSTRAINT auth_group_name_key UNIQUE (name),
	CONSTRAINT auth_group_pkey PRIMARY KEY (id)
);
CREATE INDEX auth_group_name_a6ea08ec_like ON public.auth_group USING btree (name varchar_pattern_ops);


-- public.django_content_type definition

-- Drop table

-- DROP TABLE public.django_content_type;

CREATE TABLE public.django_content_type (
	id serial NOT NULL,
	app_label varchar(100) NOT NULL,
	model varchar(100) NOT NULL,
	CONSTRAINT django_content_type_app_label_model_76bd3d3b_uniq UNIQUE (app_label, model),
	CONSTRAINT django_content_type_pkey PRIMARY KEY (id)
);


-- public.django_migrations definition

-- Drop table

-- DROP TABLE public.django_migrations;

CREATE TABLE public.django_migrations (
	id bigserial NOT NULL,
	app varchar(255) NOT NULL,
	name varchar(255) NOT NULL,
	applied timestamptz NOT NULL,
	CONSTRAINT django_migrations_pkey PRIMARY KEY (id)
);


-- public.django_session definition

-- Drop table

-- DROP TABLE public.django_session;

CREATE TABLE public.django_session (
	session_key varchar(40) NOT NULL,
	session_data text NOT NULL,
	expire_date timestamptz NOT NULL,
	CONSTRAINT django_session_pkey PRIMARY KEY (session_key)
);
CREATE INDEX django_session_expire_date_a5c62663 ON public.django_session USING btree (expire_date);
CREATE INDEX django_session_session_key_c0390e0f_like ON public.django_session USING btree (session_key varchar_pattern_ops);


-- public.login_user definition

-- Drop table

-- DROP TABLE public.login_user;

CREATE TABLE public.login_user (
	id bigserial NOT NULL,
	"password" varchar(128) NOT NULL,
	last_login timestamptz NULL,
	is_superuser bool NOT NULL,
	username varchar(150) NOT NULL,
	first_name varchar(150) NOT NULL,
	last_name varchar(150) NOT NULL,
	email varchar(254) NOT NULL,
	is_staff bool NOT NULL,
	is_active bool NOT NULL,
	date_joined timestamptz NOT NULL,
	is_admin bool NOT NULL,
	CONSTRAINT login_user_pkey PRIMARY KEY (id),
	CONSTRAINT login_user_username_key UNIQUE (username)
);
CREATE INDEX login_user_username_387fa286_like ON public.login_user USING btree (username varchar_pattern_ops);


-- public.machines_machine definition

-- Drop table

-- DROP TABLE public.machines_machine;

CREATE TABLE public.machines_machine (
	id bigserial NOT NULL,
	ip varchar(15) NULL,
	dns varchar(255) NULL,
	os varchar(20) NULL,
	risk varchar(1) NULL,
	"scanLevel" varchar(1) NULL,
	"location" varchar(30) NULL,
	periodicity varchar(1) NOT NULL,
	"nextScan" date NOT NULL,
	CONSTRAINT machines_machine_ip_and_or_dns CHECK ((((dns IS NOT NULL) AND (ip IS NULL)) OR ((dns IS NULL) AND (ip IS NOT NULL)) OR ((dns IS NOT NULL) AND (ip IS NOT NULL)))),
	CONSTRAINT machines_machine_pkey PRIMARY KEY (id)
);


-- public.machines_machineservice definition

-- Drop table

-- DROP TABLE public.machines_machineservice;

CREATE TABLE public.machines_machineservice (
	id bigserial NOT NULL,
	service varchar(24) NOT NULL,
	"version" varchar(12) NOT NULL,
	CONSTRAINT machines_machineservice_pkey PRIMARY KEY (id),
	CONSTRAINT machines_machineservice_service_version_119e1754_uniq UNIQUE (service, version)
);


-- public.workers_worker definition

-- Drop table

-- DROP TABLE public.workers_worker;

CREATE TABLE public.workers_worker (
	id bigserial NOT NULL,
	name varchar(12) NOT NULL,
	status varchar(1) NOT NULL,
	failures int4 NOT NULL,
	created timestamptz NOT NULL,
	CONSTRAINT workers_worker_pkey PRIMARY KEY (id)
);


-- public.auth_permission definition

-- Drop table

-- DROP TABLE public.auth_permission;

CREATE TABLE public.auth_permission (
	id serial NOT NULL,
	name varchar(255) NOT NULL,
	content_type_id int4 NOT NULL,
	codename varchar(100) NOT NULL,
	CONSTRAINT auth_permission_content_type_id_codename_01ab375a_uniq UNIQUE (content_type_id, codename),
	CONSTRAINT auth_permission_pkey PRIMARY KEY (id),
	CONSTRAINT auth_permission_content_type_id_2f476e4b_fk_django_co FOREIGN KEY (content_type_id) REFERENCES django_content_type(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX auth_permission_content_type_id_2f476e4b ON public.auth_permission USING btree (content_type_id);


-- public.django_admin_log definition

-- Drop table

-- DROP TABLE public.django_admin_log;

CREATE TABLE public.django_admin_log (
	id serial NOT NULL,
	action_time timestamptz NOT NULL,
	object_id text NULL,
	object_repr varchar(200) NOT NULL,
	action_flag int2 NOT NULL,
	change_message text NOT NULL,
	content_type_id int4 NULL,
	user_id int8 NOT NULL,
	CONSTRAINT django_admin_log_action_flag_check CHECK ((action_flag >= 0)),
	CONSTRAINT django_admin_log_pkey PRIMARY KEY (id),
	CONSTRAINT django_admin_log_content_type_id_c4bce8eb_fk_django_co FOREIGN KEY (content_type_id) REFERENCES django_content_type(id) DEFERRABLE INITIALLY DEFERRED,
	CONSTRAINT django_admin_log_user_id_c564eba6_fk_login_user_id FOREIGN KEY (user_id) REFERENCES login_user(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX django_admin_log_content_type_id_c4bce8eb ON public.django_admin_log USING btree (content_type_id);
CREATE INDEX django_admin_log_user_id_c564eba6 ON public.django_admin_log USING btree (user_id);


-- public.login_user_groups definition

-- Drop table

-- DROP TABLE public.login_user_groups;

CREATE TABLE public.login_user_groups (
	id bigserial NOT NULL,
	user_id int8 NOT NULL,
	group_id int4 NOT NULL,
	CONSTRAINT login_user_groups_pkey PRIMARY KEY (id),
	CONSTRAINT login_user_groups_user_id_group_id_e039d177_uniq UNIQUE (user_id, group_id),
	CONSTRAINT login_user_groups_group_id_a8810f0d_fk_auth_group_id FOREIGN KEY (group_id) REFERENCES auth_group(id) DEFERRABLE INITIALLY DEFERRED,
	CONSTRAINT login_user_groups_user_id_f6fabf84_fk_login_user_id FOREIGN KEY (user_id) REFERENCES login_user(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX login_user_groups_group_id_a8810f0d ON public.login_user_groups USING btree (group_id);
CREATE INDEX login_user_groups_user_id_f6fabf84 ON public.login_user_groups USING btree (user_id);


-- public.login_user_user_permissions definition

-- Drop table

-- DROP TABLE public.login_user_user_permissions;

CREATE TABLE public.login_user_user_permissions (
	id bigserial NOT NULL,
	user_id int8 NOT NULL,
	permission_id int4 NOT NULL,
	CONSTRAINT login_user_user_permissions_pkey PRIMARY KEY (id),
	CONSTRAINT login_user_user_permissions_user_id_permission_id_a985464b_uniq UNIQUE (user_id, permission_id),
	CONSTRAINT login_user_user_perm_permission_id_08d04f9c_fk_auth_perm FOREIGN KEY (permission_id) REFERENCES auth_permission(id) DEFERRABLE INITIALLY DEFERRED,
	CONSTRAINT login_user_user_permissions_user_id_2a4ce843_fk_login_user_id FOREIGN KEY (user_id) REFERENCES login_user(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX login_user_user_permissions_permission_id_08d04f9c ON public.login_user_user_permissions USING btree (permission_id);
CREATE INDEX login_user_user_permissions_user_id_2a4ce843 ON public.login_user_user_permissions USING btree (user_id);


-- public.machines_log definition

-- Drop table

-- DROP TABLE public.machines_log;

CREATE TABLE public.machines_log (
	cod bigserial NOT NULL,
	"date" date NOT NULL,
	"path" varchar(256) NOT NULL,
	machine_id int8 NOT NULL,
	worker_id int8 NOT NULL,
	CONSTRAINT machines_log_pkey PRIMARY KEY (cod),
	CONSTRAINT machines_log_machine_id_8ab1cb1f_fk_machines_machine_id FOREIGN KEY (machine_id) REFERENCES machines_machine(id) DEFERRABLE INITIALLY DEFERRED,
	CONSTRAINT machines_log_worker_id_cb7cc3ad_fk_workers_worker_id FOREIGN KEY (worker_id) REFERENCES workers_worker(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX machines_log_machine_id_8ab1cb1f ON public.machines_log USING btree (machine_id);
CREATE INDEX machines_log_worker_id_cb7cc3ad ON public.machines_log USING btree (worker_id);


-- public.machines_machineport definition

-- Drop table

-- DROP TABLE public.machines_machineport;

CREATE TABLE public.machines_machineport (
	id bigserial NOT NULL,
	port int4 NOT NULL,
	"scanEnabled" bool NOT NULL,
	machine_id int8 NOT NULL,
	service_id int8 NOT NULL,
	CONSTRAINT "machines_machineport_machine_id_port_scanEnabled_9719a6ff_uniq" UNIQUE (machine_id, port, "scanEnabled"),
	CONSTRAINT machines_machineport_pkey PRIMARY KEY (id),
	CONSTRAINT machines_machineport_machine_id_0d1ad4b7_fk_machines_machine_id FOREIGN KEY (machine_id) REFERENCES machines_machine(id) DEFERRABLE INITIALLY DEFERRED,
	CONSTRAINT machines_machineport_service_id_4c0e9c3f_fk_machines_ FOREIGN KEY (service_id) REFERENCES machines_machineservice(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX machines_machineport_machine_id_0d1ad4b7 ON public.machines_machineport USING btree (machine_id);
CREATE INDEX machines_machineport_service_id_4c0e9c3f ON public.machines_machineport USING btree (service_id);


-- public.machines_machineuser definition

-- Drop table

-- DROP TABLE public.machines_machineuser;

CREATE TABLE public.machines_machineuser (
	id bigserial NOT NULL,
	"userType" varchar(1) NOT NULL,
	machine_id int8 NOT NULL,
	user_id int8 NOT NULL,
	CONSTRAINT machines_machineuser_pkey PRIMARY KEY (id),
	CONSTRAINT machines_machineuser_user_id_machine_id_c413a441_uniq UNIQUE (user_id, machine_id),
	CONSTRAINT machines_machineuser_machine_id_2606e41a_fk_machines_machine_id FOREIGN KEY (machine_id) REFERENCES machines_machine(id) DEFERRABLE INITIALLY DEFERRED,
	CONSTRAINT machines_machineuser_user_id_c693a38c_fk_login_user_id FOREIGN KEY (user_id) REFERENCES login_user(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX machines_machineuser_machine_id_2606e41a ON public.machines_machineuser USING btree (machine_id);
CREATE INDEX machines_machineuser_user_id_c693a38c ON public.machines_machineuser USING btree (user_id);


-- public.machines_machineworker definition

-- Drop table

-- DROP TABLE public.machines_machineworker;

CREATE TABLE public.machines_machineworker (
	id bigserial NOT NULL,
	machine_id int8 NOT NULL,
	worker_id int8 NOT NULL,
	CONSTRAINT machines_machineworker_pkey PRIMARY KEY (id),
	CONSTRAINT machines_machinework_machine_id_757a92ee_fk_machines_ FOREIGN KEY (machine_id) REFERENCES machines_machine(id) DEFERRABLE INITIALLY DEFERRED,
	CONSTRAINT machines_machineworker_worker_id_fcab3733_fk_workers_worker_id FOREIGN KEY (worker_id) REFERENCES workers_worker(id) ON DELETE CASCADE
);
CREATE INDEX machines_machineworker_machine_id_757a92ee ON public.machines_machineworker USING btree (machine_id);
CREATE INDEX machines_machineworker_worker_id_fcab3733 ON public.machines_machineworker USING btree (worker_id);


-- public.machines_scan definition

-- Drop table

-- DROP TABLE public.machines_scan;

CREATE TABLE public.machines_scan (
	id bigserial NOT NULL,
	"date" date NOT NULL,
	status varchar(15) NOT NULL,
	machine_id int8 NOT NULL,
	worker_id int8 NOT NULL,
	CONSTRAINT machines_scan_pkey PRIMARY KEY (id),
	CONSTRAINT machines_scan_machine_id_63c61beb_fk_machines_machine_id FOREIGN KEY (machine_id) REFERENCES machines_machine(id) DEFERRABLE INITIALLY DEFERRED,
	CONSTRAINT machines_scan_worker_id_5fb2c69e_fk_workers_worker_id FOREIGN KEY (worker_id) REFERENCES workers_worker(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX machines_scan_machine_id_63c61beb ON public.machines_scan USING btree (machine_id);
CREATE INDEX machines_scan_worker_id_5fb2c69e ON public.machines_scan USING btree (worker_id);


-- public.machines_subscription definition

-- Drop table

-- DROP TABLE public.machines_subscription;

CREATE TABLE public.machines_subscription (
	id bigserial NOT NULL,
	"notificationEmail" varchar(50) NOT NULL,
	description varchar(256) NOT NULL,
	machine_id int8 NOT NULL,
	user_id int8 NOT NULL,
	CONSTRAINT machines_subscription_pkey PRIMARY KEY (id),
	CONSTRAINT machines_subscriptio_machine_id_d14fdd9a_fk_machines_ FOREIGN KEY (machine_id) REFERENCES machines_machine(id) DEFERRABLE INITIALLY DEFERRED,
	CONSTRAINT machines_subscription_user_id_2853050d_fk_login_user_id FOREIGN KEY (user_id) REFERENCES login_user(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX machines_subscription_machine_id_d14fdd9a ON public.machines_subscription USING btree (machine_id);
CREATE INDEX machines_subscription_user_id_2853050d ON public.machines_subscription USING btree (user_id);


-- public.machines_vulnerability definition

-- Drop table

-- DROP TABLE public.machines_vulnerability;

CREATE TABLE public.machines_vulnerability (
	id bigserial NOT NULL,
	risk int4 NOT NULL,
	"type" varchar(12) NOT NULL,
	description varchar(256) NOT NULL,
	"location" varchar(30) NOT NULL,
	status varchar(12) NOT NULL,
	machine_id int8 NOT NULL,
	scan_id int8 NOT NULL,
	CONSTRAINT machines_vulnerability_pkey PRIMARY KEY (id),
	CONSTRAINT machines_vulnerabili_machine_id_94fd4f02_fk_machines_ FOREIGN KEY (machine_id) REFERENCES machines_machine(id) DEFERRABLE INITIALLY DEFERRED,
	CONSTRAINT machines_vulnerability_scan_id_69aef680_fk_machines_scan_id FOREIGN KEY (scan_id) REFERENCES machines_scan(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX machines_vulnerability_machine_id_94fd4f02 ON public.machines_vulnerability USING btree (machine_id);
CREATE INDEX machines_vulnerability_scan_id_69aef680 ON public.machines_vulnerability USING btree (scan_id);


-- public.machines_vulnerabilitycomment definition

-- Drop table

-- DROP TABLE public.machines_vulnerabilitycomment;

CREATE TABLE public.machines_vulnerabilitycomment (
	id bigserial NOT NULL,
	"comment" varchar(256) NOT NULL,
	user_id int8 NOT NULL,
	vulnerability_id int8 NOT NULL,
	CONSTRAINT machines_vulnerabilitycomment_pkey PRIMARY KEY (id),
	CONSTRAINT machines_vulnerabili_vulnerability_id_607d4444_fk_machines_ FOREIGN KEY (vulnerability_id) REFERENCES machines_vulnerability(id) DEFERRABLE INITIALLY DEFERRED,
	CONSTRAINT machines_vulnerabilitycomment_user_id_7276012d_fk_login_user_id FOREIGN KEY (user_id) REFERENCES login_user(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX machines_vulnerabilitycomment_user_id_7276012d ON public.machines_vulnerabilitycomment USING btree (user_id);
CREATE INDEX machines_vulnerabilitycomment_vulnerability_id_607d4444 ON public.machines_vulnerabilitycomment USING btree (vulnerability_id);


-- public.workers_workerscancomment definition

-- Drop table

-- DROP TABLE public.workers_workerscancomment;

CREATE TABLE public.workers_workerscancomment (
	id bigserial NOT NULL,
	"comment" varchar(256) NOT NULL,
	scan_id int8 NOT NULL,
	user_cod_id int8 NOT NULL,
	CONSTRAINT workers_workerscancomment_pkey PRIMARY KEY (id),
	CONSTRAINT workers_workerscancomment_scan_id_6472ed03_fk_machines_scan_id FOREIGN KEY (scan_id) REFERENCES machines_scan(id) DEFERRABLE INITIALLY DEFERRED,
	CONSTRAINT workers_workerscancomment_user_cod_id_f6555fdd_fk_login_user_id FOREIGN KEY (user_cod_id) REFERENCES login_user(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX workers_workerscancomment_scan_id_6472ed03 ON public.workers_workerscancomment USING btree (scan_id);
CREATE INDEX workers_workerscancomment_user_cod_id_f6555fdd ON public.workers_workerscancomment USING btree (user_cod_id);


-- public.auth_group_permissions definition

-- Drop table

-- DROP TABLE public.auth_group_permissions;

CREATE TABLE public.auth_group_permissions (
	id bigserial NOT NULL,
	group_id int4 NOT NULL,
	permission_id int4 NOT NULL,
	CONSTRAINT auth_group_permissions_group_id_permission_id_0cd325b0_uniq UNIQUE (group_id, permission_id),
	CONSTRAINT auth_group_permissions_pkey PRIMARY KEY (id),
	CONSTRAINT auth_group_permissio_permission_id_84c5c92e_fk_auth_perm FOREIGN KEY (permission_id) REFERENCES auth_permission(id) DEFERRABLE INITIALLY DEFERRED,
	CONSTRAINT auth_group_permissions_group_id_b120cbf9_fk_auth_group_id FOREIGN KEY (group_id) REFERENCES auth_group(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX auth_group_permissions_group_id_b120cbf9 ON public.auth_group_permissions USING btree (group_id);
CREATE INDEX auth_group_permissions_permission_id_84c5c92e ON public.auth_group_permissions USING btree (permission_id);