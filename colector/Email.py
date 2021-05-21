from connections import connect_postgres 
import smtplib

class Email():
    def __init__(self, msg):
        self.postgre = connect_postgres()
        self.emails=[]
        self.msg=msg

    def startup(self):
        QUERY_USER_EMAILS= "select \"notificationEmail\"  from machines_subscription ms, machines_machine mm where mm.id=ms.machine_id AND (mm.dns=%s OR mm.ip=%s) "

        cur = self.postgre.cursor()
        cur.execute(QUERY_USER_EMAILS, (self.msg.value["MACHINE"], self.msg.value["MACHINE"]))
        self.emails= cur.fetchall()
        cur.close()

    def broadcast(self):
        mailserver = smtplib.SMTP('smtp.office365.com',587)
        mailserver.ehlo()
        mailserver.starttls()
        password=input("->")
        mailserver.login('margarida.martins@ua.pt', password)

        for email in self.emails:
            mailserver.sendmail('margarida.martins@ua.pt',email[0],'\n')
        
        mailserver.quit()
        