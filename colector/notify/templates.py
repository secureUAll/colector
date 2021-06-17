
from .notify import Notify


class Templates:

    @staticmethod
    def hostdown(notify: Notify, u: list, hostname:str,machineid: int):
        notify\
            .heading(f"Hello {notify.bold(u[0])},")\
            .text(f" Your host {notify.bold(hostname)} could not be reached by our system. Please check that it is available and make an instant request on the machine page. If the problem persists contact the system administrator. ")\
            .text("For more information visit your host page on Secure(UA)ll website.")\
            .button(f"https://deti-vuln-mon.ua.pt/machines/{machineid}", "Machine page")\
            .text("Remember to keep your software updated,", end="")\
            .text(notify.bold("Secure(UA)ll"))
        notify.send("[Secure(UA)ll alert] Your machine is down", u[2],"Secure(UA)ll")
        notify=notify.clean()

    def hostup_novulns(notify: Notify, u: list, hostname: str,date: str, machineid: int,  scanLevel:str):
        notify\
            .heading(f"Hello {notify.bold(u[0])},")\
            .text(f"  Congratulations &#127881;! Your host  {notify.bold(hostname)} was scanned on {notify.bold(date)} and no vulnerabilities were found.")
        if int(scanLevel)<4:
            notify.information('Information',  f'Your scrapping level is {scanLevel}, which can lead to less found vulnerabilities. You can increase this level in the host page.') 
        notify.text("For more information visit your host page on Secure(UA)ll website.")\
            .button(f"https://deti-vuln-mon.ua.pt/machines/{machineid}", "Machine page")\
            .text("Remember to keep your software updated,", end="")\
            .text(notify.bold("Secure(UA)ll"))

        notify.send("[Secure(UA)ll alert] No vulnerabilities found", u[2], "Secure(UA)ll")
        notify= notify.clean()

    def hostup_withvulns(notify: Notify, u: list, hostname: str,date: str, machineid: int, solutions:list, n_vulns: int, risk_level:int ):
        notify\
            .heading(f"Hello {notify.bold(u[0])},")\
            .text(f"Your host  {notify.bold(hostname)} was scanned on {notify.bold(date)} and {notify.bold(n_vulns)} vulnerabilities were found, with a calculated risk of {notify.bold(risk_level)}.")
        if len(solutions)>0:
            notify.card("Solutions for problems found", [{"name":s[0],"value":s[1]} for s in solutions])
            
        notify.text("For more information visit your host page on Secure(UA)ll website.")\
            .button(f"https://deti-vuln-mon.ua.pt/machines/{machineid}", "Machine page")\
            .text("Remember to keep your software updated,", end="")\
            .text(notify.bold("Secure(UA)ll"))

        notify.send(f"[Secure(UA)ll alert] {n_vulns} vulnerabilities found", u[2], "Secure(UA)ll")
        notify= notify.clean()
