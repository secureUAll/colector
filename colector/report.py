from collections import Counter

#TODO
"""
Disable Scan in some ports
"""
import logging

class Report():
    QUERY_MACHINE = '''SELECT id FROM machines_machine WHERE ip = %s or dns = %s LIMIT 1'''
    QUERY_MACHINE_PORT= '''INSERT INTO machines_machineport(port,machine_id,service_id,\"scanEnabled\") VALUES (%s,%s,%s,true) ON CONFLICT  DO NOTHING'''
    QUERY_MACHINE_SERVICE='''INSERT INTO machines_machineservice(service,version) VALUES (%s,%s) ON CONFLICT (service,version) DO UPDATE SET SERVICE=EXCLUDED.service RETURNING id'''
    QUERY_UPDATE_ADDRESS = '''UPDATE  machines_machine SET ip = %s, dns=%s, os=%s WHERE id=%s'''
    QUERY_SAVE_SCAN= "INSERT INTO machines_scan(date, status, machine_id, worker_id)   VALUES(NOW(),%s,%s,%s) RETURNING id"
    QUERY_VULNERABILITY = "INSERT INTO machines_vulnerability(risk,type,description,location,status,machine_id,scan_id) VALUES (%s, %s, %s, %s, Not Fixed, %s, %s)"

    def __init__(self, conn):
        self.conn=conn
        self.cur=None
        self.msg=None
        self.scan_id=None
        self.machine_id=None


    def report(self,msg):
        self.msg= msg
        self.cur= self.conn.cursor()

        success_scan =self.initialize_ids()
        if success_scan:
            self.save_general_info()
            self.save_vulnerabilities_info()
        self.cur.close()


    def initialize_ids(self):
        self.cur.execute(self.QUERY_MACHINE,(self.msg.value["MACHINE"],self.msg.value["MACHINE"]))
        self.machine_id= self.cur.fetchone()[0]

        status= self.check_machine_status()
        self.cur.execute(self.QUERY_SAVE_SCAN,(status,self.machine_id ,int.from_bytes(self.msg.key,"big")))
        self.scan_id= self.cur.fetchone()[0]
        self.conn.commit()

        if status=="UP":
            return True

        return False

    def check_machine_status(self):
        status= "DOWN"

        result_scan=self.msg.value["RESULTS"]
        for tool in result_scan:
            if tool['TOOL']=="nikto":
                if 'status' not in tool:
                    status="UP"
            elif tool['TOOL']=="nmap":
                if tool['run_stats']['host']['up']=='1':
                    status="UP"
            elif tool['TOOL']=="vulscan":
                if tool['state']=='up':
                    status="UP"
        return status

    def save_vulnerabilities_info(self):
        pass

    def save_general_info(self):     
        tools_general_data= self.get_tools_general_data()   

        address_ip=Counter(tools_general_data["address_ip"]).most_common(1)[0][0] if len(tools_general_data["address_ip"]) > 0 else ''
        address_dns=Counter(tools_general_data["address_name"]).most_common(1)[0][0] if len(tools_general_data["address_dns"]) > 0 else ''
        os=Counter(tools_general_data["os"]).most_common(1)[0][0] if len(tools_general_data["os"]) > 0 else ''
        self.cur.execute(self.QUERY_UPDATE_ADDRESS,(address_ip,address_dns,os,self.machine_id))
        self.conn.commit()

        for k in tools_general_data:
            if k!= "address_ip" or k!= "address_name":
                service_name=Counter(k[service_name]).most_common(1)[0][0]
                service_version=Counter(k[service_version]).most_common(1)[0][0]
                self.cur.execute(self.QUERY_MACHINE_SERVICE, (service_name,service_version))
                service_id= self.cur.fetchone()[0]
                self.conn.commit()
                self.cur.execute(self.QUERY_MACHINE_PORT, (int(k),self.machine_id,service_id))
                self.conn.commit()      

        

    def get_tools_general_data(self):
        result_scan=self.msg.value["RESULTS"]
        tools_general_data= {"address_ip":[],"address_name":[], "os":[]}

        for tool in result_scan:
            if 'address' in tool:
                logging.warning("adding ip: " + str(tool["address"]["address_ip"]) + "adding dns: " + str(tool["address"]["address_name"]) )
                if tool["address"]["address_ip"] is not None:
                    tools_general_data["address_ip"].append(tool["address"]["address_ip"])
                if tool["address"]["address_name"] is not None:
                    tools_general_data["address_name"].append(tool["address"]["address_name"])

            if 'ports' in tool:
                logging.warning("adding ports")
                ports= tool["ports"]
                for p in ports:
                    port_id = str(p["id"])
                    service_name= p["name"]
                    service_version= p["product"] + p["version"]
                    if port_id not in tools_general_data:
                        tools_general_data[port_id]={"service_name":[], "service_version":[]}
                    tools_general_data[port_id]["service_name"].append(service_name)
                    tools_general_data[port_id]["service_version"].append(service_version)
                    if "os" in p and p["os"] is not None:
                        tools_general_data["os"].append()
                    

        logging.warning("port id: " + str(port_id) + " service name: " + service_name + " service version: " +service_version )
        return tools_general_data