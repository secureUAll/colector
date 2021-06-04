from collections import Counter

#TODO
"""
Disable Scan in some ports
Adjust metrics
"""
import logging

class Report():
    QUERY_MACHINE = '''SELECT id FROM machines_machine WHERE ip = %s or dns = %s LIMIT 1'''
    QUERY_MACHINE_PORT= '''INSERT INTO machines_machineport(port,machine_id,service_id,\"scanEnabled\") VALUES (%s,%s,%s,true) ON CONFLICT  DO NOTHING'''
    QUERY_MACHINE_SERVICE='''INSERT INTO machines_machineservice(service,version) VALUES (%s,%s) ON CONFLICT (service,version) DO UPDATE SET SERVICE=EXCLUDED.service RETURNING id'''
    QUERY_UPDATE_ADDRESS = '''UPDATE  machines_machine SET ip = %s, dns=%s, os=%s WHERE id=%s'''
    QUERY_UPDATE_RISK = '''UPDATE  machines_machine SET risk=%s WHERE id=%s'''
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
            logging.warning(self.msg.value["RESULTS"] )
            self.save_general_info()
            email_info =self.save_vulnerabilities_info()
        self.cur.close()
        return email_info

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
            if (tool['TOOL']=="nikto" and 'status' not in tool) or (
                tool['TOOL']=="nmap" and tool['run_stats']['host']['up']=='1') or (
                tool['TOOL']=="vulscan" or tool['TOOL']=="zap" and  tool['state']=='up'):
                status="UP"
        return status

    def get_tools_vulnerabilities_info(self):
        num_vulns_no_risk=0
        num_vulns_risk=0
        avg_risk=0
        vulns_found=[]

        result_scan=self.msg.value["RESULTS"]
        for tool in result_scan:
            if tool['TOOL']=="nikto" and "scan" in tool:
                for vuln in tool['scan']:
                    vulns_found.append({"location":self.sanitize(vuln["url"]), "desc":self.sanitize(vuln["message"])})
                    num_vulns_no_risk +=1
            if tool['TOOL']=="zap" and "ports" in tool:
                for p in tool["ports"]:
                    for a in p.get("alerts",[]):
                        vulns_found.append({"location":self.sanitize(a["instances"]), "desc": self.sanitize(a["alert"]), "solution": self.sanitize(a["solution"].replace("<p>",""))})
                        num_vulns_risk+=1
                        avg_risk= (avg_risk*(num_vulns_risk-1) + int(a["risk"])//2)//num_vulns_risk


        return num_vulns_no_risk,avg_risk,vulns_found

    def save_vulnerabilities_info(self):
        num_vulns_no_risk,avg_risk, vulns_found= self.get_tools_vulnerabilities_info()

        for v in vulns_found:
            #risk,type,description,location,status,machine_id,scan_id
            if "cve" in v:
                pass
            else:
                self.cur.execute(self.QUERY_VULNERABILITY,('','', v["desc"], v["location"],self.machine_id, self.scan_id))
        
        if avg_risk<=2 and num_vulns_no_risk<5:
            self.cur.execute(self.QUERY_UPDATE_RISK,(1,self.machine_id))
        elif avg_risk<=4 and num_vulns_no_risk<10:
            self.cur.execute(self.QUERY_UPDATE_RISK,(1,self.machine_id))
        elif avg_risk<=6 and num_vulns_no_risk<20:
            self.cur.execute(self.QUERY_UPDATE_RISK,(1,self.machine_id))
        elif avg_risk<=8 and num_vulns_no_risk<50:
            self.cur.execute(self.QUERY_UPDATE_RISK,(1,self.machine_id))
        else:
            self.cur.execute(self.QUERY_UPDATE_RISK,(1,self.machine_id))
        self.conn.commit()
        
        return ""

    def save_general_info(self):     
        tools_general_data= self.get_tools_general_data()   

        address_ip=Counter(tools_general_data["address_ip"]).most_common(1)[0][0] if len(tools_general_data["address_ip"]) > 0 else ''
        address_dns=Counter(tools_general_data["address_name"]).most_common(1)[0][0] if len(tools_general_data["address_name"]) > 0 else ''
        os=Counter(tools_general_data["os"]).most_common(1)[0][0] if len(tools_general_data["os"]) > 0 else ''
        self.cur.execute(self.QUERY_UPDATE_ADDRESS,(address_ip,address_dns,os,self.machine_id))
        self.conn.commit()

        for k in tools_general_data.keys():
            if k!= "address_ip" and k!="os"  and  k!= "address_name" and tools_general_data[k]["service_name"] and tools_general_data[k]["service_version"]:
                service_name=Counter(tools_general_data[k]["service_name"]).most_common(1)[0][0] if len(tools_general_data[k]["service_version"])>0 else 'NOT DETECTED'
                service_version=Counter(tools_general_data[k]["service_version"]).most_common(1)[0][0] if len(tools_general_data[k]["service_version"])>0 else 'NOT DETECTED'
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
                    if tool["TOOL"] == "zap":
                        port_id = str(p["port"])
                        if port_id not in tools_general_data:
                            tools_general_data[port_id]={"service_name":[], "service_version":[]}
                    else:
                        port_id = str(p["id"])
                        if port_id not in tools_general_data:
                            tools_general_data[port_id]={"service_name":[], "service_version":[]}
                        service_name= p["name"]
                        service_version= p["product"] + p["version"] if p["product"] is not None else None
                        tools_general_data[port_id]["service_name"].append(service_name)
                        tools_general_data[port_id]["service_version"].append(service_version) if service_version is not None else None
                        if "os" in p and p["os"] is not None:
                            tools_general_data["os"].append(p["os"])
                        logging.warning("port id: " + str(port_id) + " service name: " + service_name + " service version: " +service_version )
        return tools_general_data

    def sanitize(self, text):
        return text.replace("'","''")