from notify import Notify
#from connections import connect_postgres 
import smtplib
from notify.templates import Templates
from notify.email import Email

class NotificationSender():
    def __init__(self, msg):
        #self.postgre = connect_postgres()
        self.emails=[]
        self.msg=msg

    """
    def startup(self):
        QUERY_USER_EMAILS= "select \"notificationEmail\"  from machines_subscription ms, machines_machine mm where mm.id=ms.machine_id AND (mm.dns=%s OR mm.ip=%s) "

        cur = self.postgre.cursor()
        cur.execute(QUERY_USER_EMAILS, (self.msg.value["MACHINE"], self.msg.value["MACHINE"]))
        self.emails= cur.fetchall()
        cur.close()
    """
    def broadcast(self):
        Templates.hostdown(Notify(), "Manel", "xxx@ua.pt", 2, ["margarida.martins@ua.pt"])
        
        