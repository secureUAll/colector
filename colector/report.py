from collections import Counter
import logging
import re

class Report():
    QUERY_MACHINE = '''SELECT id, ip, dns FROM machines_machine WHERE id=%s'''
    QUERY_MACHINE_ACTIVE = '''SELECT active FROM machines_machine WHERE id=%s'''
    QUERY_MACHINE_PORT= '''INSERT INTO machines_machineport(port,machine_id,service_id,\"scanEnabled\", vulnerable) VALUES (%s,%s,%s,true, %s) ON CONFLICT  DO NOTHING'''
    QUERY_MACHINE_SERVICE='''INSERT INTO machines_machineservice(service,version) VALUES (%s,%s) ON CONFLICT (service,version) DO UPDATE SET SERVICE=EXCLUDED.service RETURNING id'''
    QUERY_NEW_MACHINE = '''INSERT INTO machines_machine(ip,dns, \"scanLevel\", periodicity, \"nextScan\", active, created, updated) VALUES(%s,%s,'2','W',NOW(), true, NOW(), NOW() ) RETURNING id'''
    QUERY_UPDATE_ADDRESS = '''UPDATE  machines_machine SET ip = %s, dns=%s WHERE id=%s'''
    QUERY_UPDATE_OS = '''UPDATE machines_machine SET os=%s WHERE id=%s'''
    QUERY_UPDATE_STATUS = '''UPDATE machines_machine SET active=%s WHERE id=%s'''
    QUERY_UPDATE_RISK = '''UPDATE  machines_machine SET risk=%s WHERE id=%s'''
    QUERY_SAVE_SCAN= "INSERT INTO machines_scan(date, status, machine_id, worker_id)   VALUES(NOW(),%s,%s,%s) RETURNING id"
    QUERY_VULNERABILITY = "INSERT INTO machines_vulnerability(risk,type,description,location,status,created, updated,machine_id,scan_id) VALUES (%s, %s, %s, %s, \'Not Fixed\',NOW(),NOW(),%s, %s)"
    QUERY_DELETE_MACHINE_WORKER = "DELETE FROM machines_machineworker  WHERE machine_id=%s"


    def __init__(self, conn):
        self.conn=conn
        self.cur=None
        self.msg=None
        self.scan_id=None
        self.machine_id=None
        self.active=None


    def report(self,msg):
        self.msg= msg
        self.cur= self.conn.cursor()
        
        logging.info(f"Message form worker {msg}")

        success_scan =self.initialize_ids()

        #if scan was successfull retrive solutions
        if success_scan:
            logging.info("Scan was sucessfull")
            services_found=self.save_general_info()
            nvulns, solutions =self.save_vulnerabilities_info(services_found)
            self.cur.close()
            return {"MACHINE_ID": self.machine_id, "SOLUTIONS":solutions, "NVULNS": nvulns}

        return {"MACHINE_ID": self.machine_id}

    #
    # check host status returned by the tools
    # seeing if the machine no loger exist or was updated
    #
    def initialize_ids(self):
        self.machine_id= self.msg.value["MACHINE_ID"]

        status= self.check_machine_status()

        #in case of multiple workers scannig an inactive machine
        self.check_machine_active()

        self.cur.execute(self.QUERY_SAVE_SCAN,(status,self.machine_id ,int.from_bytes(self.msg.key,"big")))
        self.scan_id= self.cur.fetchone()[0]
        self.conn.commit()

        if status=="UP":
            return True

        return False

    #
    # check host status returned by the tools
    #
    def check_machine_status(self):
        status= "DOWN"

        result_scan=self.msg.value["RESULTS"]
        for tool in result_scan:
            if (tool['TOOL']=="nikto" and 'status' not in tool) or (
                tool['TOOL']=="nmap" and tool['run_stats']['host']['up']=='1') or (
                (tool['TOOL']=="vulscan" or tool['TOOL']=="zap") and  tool['state']=='up'):
                status="UP"
        return status

    #
    # get active parameter of the host
    #
    def check_machine_active(self):
        self.cur.execute(self.QUERY_MACHINE_ACTIVE, (self.machine_id,))
        self.active= self.cur.fetchone()[0]

    #
    # process vulnerabilities found by the tools
    #
    def get_tools_vulnerabilities_info(self, services_found):
        num_vulns_no_risk=0
        risk=[0,0,0,0,0]
        vulns_found=[]
        solutions=[]

        result_scan=self.msg.value["RESULTS"]
        for tool in result_scan:

            # get vulnerabilities from nikto
            if tool['TOOL']=="nikto" and "scan" in tool:
                for vuln in tool['scan']:
                    # when nikto detects software outdated
                    if "appears to be outdated" in vuln["message"]:
                        vulns_found.append({"risk":3,"location":self.sanitize(vuln["url"]), "type":"software outdated", "desc":self.sanitize(vuln["message"])})
                        solutions.append((self.sanitize(vuln["message"]),"Update your software!"))
                        risk[2]+=1
                    else:
                        vulns_found.append({"location":self.sanitize(vuln["url"]), "desc":self.sanitize(vuln["message"])})
                        num_vulns_no_risk +=1
            
            # get vulnerabilities from zap
            if tool['TOOL']=="zap" and "ports" in tool:
                for p in tool["ports"]:
                    for a in p.get("alerts",[]):
                        vulns_found.append({"risk": int(a["risk"]) +1 ,"location":self.sanitize(' '.join(a["instances"])), "desc": self.sanitize(a["alert"])})
                        solutions.append((self.sanitize(a["alert"]),self.sanitize(a["solution"].replace("<p>",""))))
                        risk[int(a["risk"])]+= 1
            
            # get vulnerabilities from vulscan
            if tool['TOOL']=="nmap_vulscan" and "output" in tool:
                for vuln in tool["output"]:
                    if any([s[0] in vuln and s[1] in vuln for s in services_found]):
                        logging.warning("Added vulsacan vuln"+ vuln)
                        vulns_found.append({"cve": vuln})
            
            #get vulnerabilities from sql_map
            if tool['TOOL']=='sqlmap' and tool['scan']!=[]:
                vulns=tool['scan']
                for v in vulns:
                    vulns_found.append({"risk":5, "location": f"Parameters: {' '.join(v[1])}", "type": "injection", "desc": f"{vuln[0]} sql injection"})
                    solutions.append((f"{vuln[0]} sql injection","Make sure you sanitize all parameters! For more information consult: https://owasp.org/www-community/attacks/SQL_Injection"))
                    risk[4]+= 1


        return num_vulns_no_risk,risk,vulns_found,solutions

    #
    # save vulnerabilities processed
    #
    def save_vulnerabilities_info(self,services_found):
        num_vulns_no_risk,risk, vulns_found, solutions= self.get_tools_vulnerabilities_info(services_found)
        logging.warning(vulns_found)
        for v in vulns_found:
            #risk,type,description,location,status,machine_id,scan_id
            if "cve" in v:
                pass
            else:
                if "type" in v:
                    self.cur.execute(self.QUERY_VULNERABILITY,(v["risk"],v["type"], v["desc"], v["location"],self.machine_id, self.scan_id))
                elif "risk" in v:
                    self.cur.execute(self.QUERY_VULNERABILITY,(v["risk"],'', v["desc"], v["location"],self.machine_id, self.scan_id))
                else:
                    self.cur.execute(self.QUERY_VULNERABILITY,(0,'', v["desc"], v["location"],self.machine_id, self.scan_id))

        if sum(risk[1:])==0 and num_vulns_no_risk<5:
            self.cur.execute(self.QUERY_UPDATE_RISK,(1,self.machine_id))
        elif sum(risk[2:])==0 and num_vulns_no_risk<10:
            self.cur.execute(self.QUERY_UPDATE_RISK,(2,self.machine_id))
        elif sum(risk[3:])==0 and num_vulns_no_risk<20:
            self.cur.execute(self.QUERY_UPDATE_RISK,(3,self.machine_id))
        elif risk[4]==0 and num_vulns_no_risk<50:
            self.cur.execute(self.QUERY_UPDATE_RISK,(4,self.machine_id))
        else:
            self.cur.execute(self.QUERY_UPDATE_RISK,(5,self.machine_id))
        self.conn.commit()
        
        total_nvulns= num_vulns_no_risk + len(vulns_found)
        return total_nvulns, solutions


    #
    # save general host information processed
    #
    def save_general_info(self):     
        tools_general_data= self.get_tools_general_data()   

        address_ip=Counter(tools_general_data["address_ip"]).most_common(1)[0][0] if len(tools_general_data["address_ip"]) > 0 else None
        address_dns=Counter(tools_general_data["address_name"]).most_common(1)[0][0] if len(tools_general_data["address_name"]) > 0 else None
        os=Counter(tools_general_data["os"]).most_common(1)[0][0] if len(tools_general_data["os"]) > 0 else None
        
        if address_ip is not None and address_dns is not None:
            
            #See if machine is new          
            self.cur.execute(self.QUERY_MACHINE,(self.machine_id,))
            machine_info= self.cur.fetchone()
            if address_dns!= machine_info[2]:
                self.update_machine(address_ip,address_dns)
            else:
                self.cur.execute(self.QUERY_UPDATE_ADDRESS,(address_ip,address_dns,self.machine_id))
        
        if os is not None:
            self.cur.execute(self.QUERY_UPDATE_OS,(os,self.machine_id))
        self.conn.commit()

        services_found=[]
        for k in tools_general_data.keys():
            if k!= "address_ip" and k!="os"  and  k!= "address_name" and tools_general_data[k]["service_name"] and tools_general_data[k]["service_version"]:
                service_name=Counter(tools_general_data[k]["service_name"]).most_common(1)[0][0] if len(tools_general_data[k]["service_version"])>0 else 'NOT DETECTED'
                service_version=Counter(tools_general_data[k]["service_version"]).most_common(1)[0][0] if len(tools_general_data[k]["service_version"])>0 else 'NOT DETECTED'
                
                self.cur.execute(self.QUERY_MACHINE_SERVICE, (service_name,service_version))
                service_id= self.cur.fetchone()[0]
                self.conn.commit()

                if "malware" in k:
                    self.cur.execute(self.QUERY_MACHINE_PORT, (int(k),self.machine_id,service_id,True))
                else:
                    self.cur.execute(self.QUERY_MACHINE_PORT, (int(k),self.machine_id,service_id,False))

                self.conn.commit()  

                services_found.append((service_name,service_version)) 

        return services_found

        
    #
    # process general host information found by the tools
    #
    def get_tools_general_data(self):
        result_scan=self.msg.value["RESULTS"]
        tools_general_data= {"address_ip":[],"address_name":[], "os":[]}

        for tool in result_scan:

            # there is information about the host address
            if 'address' in tool:
                logging.warning("adding ip: " + str(tool["address"]["address_ip"]) + "adding dns: " + str(tool["address"]["address_name"]) )
                if tool["address"]["address_ip"] is not None:
                    tools_general_data["address_ip"].append(tool["address"]["address_ip"])
                if tool["address"]["address_name"] is not None:
                    tools_general_data["address_name"].append(tool["address"]["address_name"])

            # there is information about the host ports
            if 'ports' in tool:
                logging.warning("adding ports")
                ports= tool["ports"]
                for p in ports:
                    if tool["TOOL"] == "zap":
                        port_id = str(p["port"])
                        if port_id not in tools_general_data:
                            tools_general_data[port_id]={"service_name":[], "service_version":[]}
                    
                    elif tool["TOOL"] == "nmap_malware":
                        port_id= str(p["port"])
                        if port_id not in tools_general_data:
                            tools_general_data[port_id]={"service_name":[], "service_version":[], "malware": p["malware"]}

                    else:
                        port_id = str(p["id"])
                        if port_id not in tools_general_data:
                            tools_general_data[port_id]={"service_name":[], "service_version":[]}
                        service_name= p["name"]
                        service_version= p["product"] if p["product"] is not None else  "" 
                        service_version= service_version+ p["version"] if p["version"] is not None else  service_version
                        tools_general_data[port_id]["service_name"].append(service_name)
                        tools_general_data[port_id]["service_version"].append(service_version) if service_version is not None or service_version!="" else None
                        if "os" in p and p["os"] is not None:
                            tools_general_data["os"].append(p["os"])
                        logging.warning("port id: " + str(port_id) + " service name: " + str(service_name) + " service version: " + str(service_version) )
        
        return tools_general_data

    #
    # If a new host was found while scanning update
    #
    def update_machine(self, address_ip, address_dns):

        if self.active:
            #set currents machine as inactive
            self.cur.execute(self.QUERY_UPDATE_STATUS, (self.machine_id,))
            self.conn.commit()

            #Remove machine from workers
            self.cur.execute(self.QUERY_DELETE_MACHINE_WORKER, (self.machine_id,))
            self.conn.commit()

            #create new machine
            self.cur.execute(self.QUERY_NEW_MACHINE, (address_ip, address_dns))
            self.machine_id = self.cur.fetchone()[0]
            self.conn.commit()
        
        #save scan
        self.cur.execute(self.QUERY_SAVE_SCAN,("UP",self.machine_id ,int.from_bytes(self.msg.key,"big")))
        self.scan_id= self.cur.fetchone()[0]
        self.conn.commit()

    def sanitize(self, text):
        return text.replace("'","''")

    