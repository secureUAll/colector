#TODO
"""
Disable Scan in some ports
"""


class Report():
    QUERY_MACHINE = '''SELECT id FROM machines_machine WHERE ip = %s or dns = %s LIMIT 1'''
    QUERY_MACHINE_PORT= '''INSERT INTO machines_machineport(port,machine_id,service_id) VALUES (%s,%s,%s)'''
    QUERY_MACHINE_SERVICE='''INSERT INTO machines_machineservice(service,version) VALUES (%s,%s) RETURNING id'''
    QUERY_UPDATE_ADDRESS = '''UPDATE  machines_machine SET ip = %s, dns=%s WHERE id=%s'''
    QUERY_SAVE_SCAN= "INSERT INTO machines_scan(date, status, machine_id, worker_id)   VALUES(NOW(),%s,%s,%s) RETURNING id"

    def __init__(self, conn):
        self.conn=conn
        self.cur=None
        self.msg=None
        self.scan_id=None
        self.machine_id=None

    def report(self,msg):
        self.msg= msg
        self.cur= self.conn.cursor()

        self.initialize_ids()
        self.save_general_info()
        cur.close()


    def initialize_ids(self):
        self.cur.execute(self.QUERY_MACHINE,(self.msg.value["MACHINE"],self.msg.value["MACHINE"]))
        self.machine_id= self.cur.fetchone()[0]

        self.cur.execute(self.QUERY_SAVE_SCAN,("2",self.machine_id ,int.from_bytes(self.msg.key,"big")))
        self.scan_id= self.cur.fetchone()[0]
        self.conn.commit()


    def save_general_info(self):
        result_scan=self.msg.value["RESULTS"]
        address_ip= result_scan["address"]["addr"]
        address_dns= result_scan["address"]["addrname"]

        self.cur.execute(self.QUERY_UPDATE_ADDRESS,(address_ip,address_dns,self.machine_id))
        self.conn.commit()

        ports= result_scan["scan"]
        for p in ports:
            self.save_port(p,self.cur)
        

    def save_port(self,port,cur):
        port_id = port["portid"]
        service_name= port["service"]["connection"]
        service_version= port["service"]["product"] + port["service"]["version"]

        self.cur.execute(self.QUERY_MACHINE_SERVICE, (service_name,service_version))
        service_id= cur.fetchone()[0]
        self.conn.commit()
        self.cur.execute(self.QUERY_MACHINE_PORT, (port_id,self.machine_id,service_id))
        self.conn.commit()

