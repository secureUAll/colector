
from notify.slack import SlackNotify
from notify.email import EmailNotify
#from connections import connect_postgres 
from notify.templates import Templates


class NotificationSender():
    def __init__(self, msg=None):
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
        Templates.hostdown(EmailNotify(), "Manel", "xxx@ua.pt", 2, ["margarida.martins@ua.pt"])
        Templates.hostup_novulns(EmailNotify(), "Manel", "xxx@ua.pt", "2020-03-03" , 2, ["margarida.martins@ua.pt"],2)
        Templates.hostup_novulns(EmailNotify(), "Manel", "xxx@ua.pt", "2020-03-03" , 2, ["margarida.martins@ua.pt"],4)
        Templates.hostup_withvulns(EmailNotify(),"Manel", "xxx@ua.pt", "2020-03-03" , 2, ["margarida.martins@ua.pt"], [("vuln1", "solution1"), ("vuln2", "solution2")],2,3 )


