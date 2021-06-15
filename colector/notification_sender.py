from notify.slack import SlackNotify
from notify.email import EmailNotify
from notify.templates import Templates
from connections import   connect_postgres

import logging

class NotificationSender():
    def __init__(self, info):
        self.conn = connect_postgres()
        self.info= info


    def run(self):
        logging.warning("Notifications for machine" + str(self.info["MACHINE_ID"]))

        QUERY_USER_EMAILS= "select lu.first_name, ln.type, ln.value  from  machines_machine mm, machines_machineuser mu, login_user lu, login_usernotification ln where mm.id=%s AND mm.id=mu.machine_id  AND mu.user_id=lu.id AND ln.id=lu.id"
        
        QUERY_MACHINE = "select ip, dns, \"scanLevel\", risk from machines_machine where id=%s"
        QUERY_SCAN= "select date from  machines_scan where machine_id=%s  ORDER BY date  DESC LIMIT 1"

        cur = self.conn.cursor()

        # name and where to send notification
        cur.execute(QUERY_USER_EMAILS, (self.info["MACHINE_ID"],))
        user_info= cur.fetchall()

        if len(user_info)>0:
            logging.warning("User info")
            logging.warning(user_info)
            
            cur.execute(QUERY_MACHINE, (self.info["MACHINE_ID"],))
            #ip, dns, scanLevel and risk
            data= cur.fetchone()

            cur.execute(QUERY_SCAN, (self.info["MACHINE_ID"],))
            scan_date= cur.fetchone()[0]
            cur.close()
            self.broadcast(user_info,data, scan_date)
    
    def broadcast(self, user_info, data, scan_date):
        #get dns or ip if dns not present
        host= data[1] if data[1] != '' else data[0]

        if "NVULNS" in self.info:
            if(self.info["NVULNS"]==0):
                Templates.hostup_novulns(EmailNotify(), user_info, host, scan_date , self.info["MACHINE_ID"] ,data[2])
            else:
                Templates.hostup_withvulns(EmailNotify(),user_info, host, scan_date , self.info["MACHINE_ID"] , self.info["SOLUTIONS"],self.info["NVULNS"],data[3] )
        else:
            Templates.hostdown(EmailNotify(), user_info, host, self.info["MACHINE_ID"])
        
        