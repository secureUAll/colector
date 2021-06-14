
from .notify import Notify


class Templates:

    @staticmethod
    def hostdown(notify: Notify, name: str, hostname: str, machineid: int, recipient: list):
        notify\
            .heading(f"Hello {notify.bold(name)},")\
            .text(f" Your host {notify.bold(hostname)} could not be reached by our system. Please check that it is available and make an instant request on the machine page. If the problem persists contact the system administrator. ")\
            .text("For more information visit your host page on Secure(UA)ll website.")\
            .button(f"https://deti-vuln-mon.ua.pt/machines/{machineid}", "Machine page")\
            .text("Remember to keep your software updated,", end="")\
            .text(notify.bold("Secure(UA)ll"))
        notify.send("[Secure(UA)ll alert] Your machine is down", recipient)

    def hostup_novulns(notify: Notify, name: str, hostname: str,date: str, machineid: int, recipient: list, scanLevel:int):
        notify\
            .heading(f"Hello {notify.bold(name)},")\
            .text(f"  Congratulations &#127881;! Your host  {notify.bold(hostname)} was scanned on {notify.bold(date)} and no vulnerabilities were found.")
        if scanLevel<4:
            notify.information('Information',  f'Your scrapping level is {scanLevel}, which can lead to less found vulnerabilities. You can increase this level in the host page.') 
        notify.text("For more information visit your host page on Secure(UA)ll website.")\
            .button(f"https://deti-vuln-mon.ua.pt/machines/{machineid}", "Machine page")\
            .text("Remember to keep your software updated,", end="")\
            .text(notify.bold("Secure(UA)ll"))

        notify.send("[Secure(UA)ll alert] Your machine is down", recipient)

    def hostup_withvulns(notify: Notify, name: str, hostname: str,date: str, machineid: int, recipient: list, solutions:list, n_vulns: int, risk_level:int ):
        notify\
            .heading(f"Hello {notify.bold(name)},")\
            .text(f"Your host  {notify.bold(hostname)} was scanned on {notify.bold(date)} and {notify.bold(n_vulns)} vulnerabilities were found, with a calculated risk of {notify.bold(risk_level)}.")\
            .cardStart()\
            .heading2(f"Solutions for problems found")
        for s in solutions:
            notify.heading3(s[0])\
                .text(s[1])

        notify.cardEnd()\
            .text("For more information visit your host page on Secure(UA)ll website.")\
            .button(f"https://deti-vuln-mon.ua.pt/machines/{machineid}", "Machine page")\
            .text("Remember to keep your software updated,", end="")\
            .text(notify.bold("Secure(UA)ll"))

        notify.send("[Secure(UA)ll alert] Your machine is down", recipient)