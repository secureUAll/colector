from notify.teams import TeamsNotify
from notify.email import EmailNotify
from notify.templates import Templates
from connections import   connect_postgres

import logging

class NotificationSender():
    def __init__(self, info):
        self.conn = connect_postgres()
        self.info= info

    #
    #   Send notification to the host users
    #
    def run(self):
        logging.info("Notifications for machine" + str(self.info["MACHINE_ID"]))

        QUERY_USER_EMAILS= "select lu.first_name, ln.type, ln.value  from  machines_machine mm, machines_machineuser mu, login_user lu, login_usernotification ln where mm.id=%s AND mm.id=mu.machine_id  AND mu.user_id=lu.id AND ln.user_id=lu.id"
        
        QUERY_MACHINE = "select ip, dns, \"scanLevel\", risk from machines_machine where id=%s"
        QUERY_SCAN= "select date from  machines_scan where machine_id=%s  ORDER BY date  DESC LIMIT 1"

        cur = self.conn.cursor()

        # name and where to send notification
        cur.execute(QUERY_USER_EMAILS, (self.info["MACHINE_ID"],))
        user_info= cur.fetchall()

        if len(user_info)>0:
            logging.info(f"User info:\n {user_info[0]}")
            logging.info(user_info)
            
            cur.execute(QUERY_MACHINE, (self.info["MACHINE_ID"],))
            
            #ip, dns, scanLevel and risk
            data= cur.fetchone()

            #scan date
            cur.execute(QUERY_SCAN, (self.info["MACHINE_ID"],))
            scan_date= cur.fetchone()[0]
            cur.close()
            
            # send notification
            self.broadcast(user_info,data, scan_date)
    
    #
    # For each user send notification based on its profile configuration
    #
    def broadcast(self, user_info, data, scan_date):
        #get dns or ip if dns not present
        host= data[1] if data[1] != '' else data[0]

        for u in user_info:

            # see type of notification
            notify= EmailNotify() if u[1]=="Email" else TeamsNotify()

            if "NVULNS" in self.info:

                # Host up no vulnerabilities found
                if(self.info["NVULNS"]==0):
                    Templates.hostup_novulns(notify, u, host, scan_date , self.info["MACHINE_ID"] ,data[2])
                
                # Host up with vulnerabilities found
                else:
                    Templates.hostup_withvulns(notify,u, host, scan_date , self.info["MACHINE_ID"] , self.info["SOLUTIONS"],self.info["NVULNS"],data[3] )
            
            # Host down
            else:
                Templates.hostdown(notify, u, host, self.info["MACHINE_ID"])
        
        