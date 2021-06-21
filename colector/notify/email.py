from __future__ import annotations

from .notify import Notify
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText



class EmailNotify(Notify):
    

    def __init__(self):
        # <head>
        self._email = """
            <!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w3.org/TR/REC-html40/loose.dtd">
            <html>
              <head>
                <!-- Compiled with Bootstrap Email version: 1.0.0.alpha3.1 -->
                <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
                
                        <style type="text/css">
                        body,table,td{font-family:Helvetica,Arial,sans-serif !important}.ExternalClass{width:100%}.ExternalClass,.ExternalClass p,.ExternalClass span,.ExternalClass font,.ExternalClass td,.ExternalClass div{line-height:150%}a{text-decoration:none}*{color:inherit}a[x-apple-data-detectors],u+#body a,#MessageViewBody a{color:inherit;text-decoration:none;font-size:inherit;font-family:inherit;font-weight:inherit;line-height:inherit}img{-ms-interpolation-mode:bicubic}table:not([class^=s-]){font-family:Helvetica,Arial,sans-serif;mso-table-lspace:0pt;mso-table-rspace:0pt;border-spacing:0px;border-collapse:collapse}table:not([class^=s-]) td{border-spacing:0px;border-collapse:collapse}@media screen and (max-width: 600px){.w-full,.w-full>tbody>tr>td{width:100% !important}.p-3:not(table),.p-3:not(.btn)>tbody>tr>td,.p-3.btn td a{padding:12px !important}.p-5:not(table),.p-5:not(.btn)>tbody>tr>td,.p-5.btn td a{padding:20px !important}*[class*=s-lg-]>tbody>tr>td{font-size:0 !important;line-height:0 !important;height:0 !important}.s-0>tbody>tr>td{font-size:0 !important;line-height:0 !important;height:0 !important}.s-2>tbody>tr>td{font-size:8px !important;line-height:8px !important;height:8px !important}.s-3>tbody>tr>td{font-size:12px !important;line-height:12px !important;height:12px !important}.s-5>tbody>tr>td{font-size:20px !important;line-height:20px !important;height:20px !important}}
            
                      </style>
            </head>
        """
        # <body>
        self._email += """
              <body class="bg-light" style="outline: 0; width: 100%; min-width: 100%; height: 100%; -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; font-family: Helvetica, Arial, sans-serif; line-height: 24px; font-weight: normal; font-size: 16px; -moz-box-sizing: border-box; -webkit-box-sizing: border-box; box-sizing: border-box; color: #000000; margin: 0; padding: 0; border: 0;" bgcolor="#f7fafc">
                <table class="bg-light body" valign="top" role="presentation" border="0" cellpadding="0" cellspacing="0" style="outline: 0; width: 100%; min-width: 100%; height: 100%; -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; font-family: Helvetica, Arial, sans-serif; line-height: 24px; font-weight: normal; font-size: 16px; -moz-box-sizing: border-box; -webkit-box-sizing: border-box; box-sizing: border-box; color: #000000; margin: 0; padding: 0; border: 0;" bgcolor="#f7fafc">
                  <tbody>
                    <tr>
                      <td valign="top" style="line-height: 24px; font-size: 16px; margin: 0;" align="left" bgcolor="#f7fafc">
                        
        """
        # Secure(UA)ll Header
        self._email += """
            <a href="https://deti-vuln-mon.ua.pt/" style="color: #0d6efd;">
                  <table class="bg-dark text-white p-5 w-full" role="presentation" border="0" cellpadding="0" cellspacing="0" style="color: #ffffff; width: 100%;" bgcolor="#1a202c" width="100%">
              <tbody>
                <tr>
                  <td style="line-height: 24px; font-size: 16px; color: #ffffff; width: 100%; margin: 0; padding: 20px;" align="left" bgcolor="#1a202c" width="100%">
                    
                      <img src="https://deti-vuln-mon.ua.pt/static/assets/images/logos/email.png" style="height: auto; line-height: 100%; outline: none; text-decoration: none; display: block; border: 0 none; width:100%;">
                      <p class="text-center" style="line-height: 24px; font-size: 16px; width: 100%; margin: 0;" align="center">UA security exposure sentinel</p>
                    
                  </td>
                </tr>
              </tbody>
            </table>
                </a>
        """
        # Main container
        self._email += """
            <!-- Main container -->
            <table class="s-5 w-full" role="presentation" border="0" cellpadding="0" cellspacing="0" style="width: 100%;" width="100%">
          <tbody>
            <tr>
              <td style="line-height: 20px; font-size: 20px; width: 100%; height: 20px; margin: 0;" align="left" width="100%" height="20">
                 
              </td>
            </tr>
          </tbody>
        </table>
        <table class="container p-5" role="presentation" border="0" cellpadding="0" cellspacing="0" style="width: 100%;">
          <tbody>
            <tr>
              <td align="center" style="line-height: 24px; font-size: 16px; margin: 0; padding: 20px;">
                <!--[if (gte mso 9)|(IE)]>
                  <table align="center" role="presentation">
                    <tbody>
                      <tr>
                        <td width="600">
                <![endif]-->
                <table align="center" role="presentation" border="0" cellpadding="0" cellspacing="0" style="width: 100%; max-width: 600px; margin: 0 auto;">
                  <tbody>
                    <tr>
                      <td style="line-height: 24px; font-size: 16px; margin: 0;" align="left">
                        
        """

    def heading(self, h1: str, end="\n") -> EmailNotify:
        self._email += f'<h2 class="" style="padding-top: 0; padding-bottom: 0; font-weight: 500; vertical-align: baseline; font-size: 32px; line-height: 38.4px; margin: 0;" align="left">{h1}{end}'
        if end=="\n":
            return self._spacebelow()
        return self

    def heading2(self, h2: str, end="\n") -> EmailNotify:
        self._email += f'<h4 style="padding-top: 0; padding-bottom: 0; font-weight: 500; vertical-align: baseline; font-size: 24px; line-height: 28.8px; margin: 0;" align="left">{h2},{end}</h4>'
        if end == "\n":
          return self._spacebelow()
        return self

    def heading3(self, h2: str, end="\n"):
        self._email += f'<h5 class="text-muted" style="color: #718096; padding-top: 0; padding-bottom: 0; font-weight: 500; vertical-align: baseline; font-size: 20px; line-height: 24px; margin: 0;" align="left">{h2}</h5>'
        if end == "\n":
            return self._spacebelow()
        return self

    def text(self, text: str, end="\n") -> EmailNotify:
        self._email += f'<p class="" style="line-height: 24px; font-size: 16px; width: 100%; margin: 0;" align="left">{text}{end}'
        if end == "\n":
            return self._spacebelow()
        return self

    def information(self, title: str, info: str, end="\n") -> EmailNotify:
        self._email += f"""
              <div class="secureuall-alert" style="border-radius: .25rem; border: 1px solid #92d400;">
                <table class="p-3" role="presentation" border="0" cellpadding="0" cellspacing="0">
                  <tbody>
                    <tr>
                      <td style="line-height: 24px; font-size: 16px; margin: 0; padding: 12px;" align="left">
                        <div class="">
                          <p class="small" style="line-height: 24px; font-size: 80%; width: 100%; margin: 0;" align="left"><b>{title}</b></p>
                          <p class="small" style="line-height: 24px; font-size: 80%; width: 100%; margin: 0;" align="left">{info} </p>
                <table class="s-0 w-full" role="presentation" border="0" cellpadding="0" cellspacing="0" style="width: 100%;" width="100%">
                  <tbody>
                    <tr>
                      <td style="line-height: 0; font-size: 0; width: 100%; height: 0; margin: 0;" align="left" width="100%" height="0">
                         
                      </td>
                    </tr>
                  </tbody>
                </table>
                          </div>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
        """
        if end == "\n":
            return self._spacebelow()
        return self

    def button(self, url: str, text:str, end="\n") -> EmailNotify:
        self._email += f"""
            <div class="d-flex" style="display: flex;">
                    <a class="mx-auto btn-secureuall " href="{url}" style="color: #ffffff !important; background-color: #92d400 !important; display: inline-block; line-height: 1.5; text-align: center; text-decoration: none; vertical-align: middle; cursor: pointer; -webkit-user-select: none; -moz-user-select: none; user-select: none; border-radius: .25rem; margin-left: auto; margin-right: auto; padding: .375rem .75rem;">
                        {text}
                    </a>
                  </div>
            <table class="s-3 w-full" role="presentation" border="0" cellpadding="0" cellspacing="0" style="width: 100%;" width="100%">
              <tbody>
                <tr>
                  <td style="line-height: 12px; font-size: 12px; width: 100%; height: 12px; margin: 0;" align="left" width="100%" height="12">
                  </td>
                </tr>
              </tbody>
            </table>
        """
        if end=="\n":
            return self._spacebelow()
        return self

    def card(self, title: str, content: list, end="\n") -> Notify:
        # Card start
        self._email += """
            <table class="s-5 w-full" role="presentation" border="0" cellpadding="0" cellspacing="0" style="width: 100%;" width="100%">
              <tbody>
                <tr>
                  <td style="line-height: 20px; font-size: 20px; width: 100%; height: 20px; margin: 0;" align="left" width="100%" height="20">

                  </td>
                </tr>
              </tbody>
            </table>
            <table class="card" role="presentation" border="0" cellpadding="0" cellspacing="0" style="border-radius: 6px; border-collapse: separate !important; width: 100%; overflow: hidden; border: 1px solid #e2e8f0;" bgcolor="#ffffff">
              <tbody>
                <tr>
                  <td style="line-height: 24px; font-size: 16px; width: 100%; margin: 0;" align="left" bgcolor="#ffffff">

                    <table class="card-body" role="presentation" border="0" cellpadding="0" cellspacing="0" style="width: 100%;">
              <tbody>
                <tr>
                  <td style="line-height: 24px; font-size: 16px; width: 100%; margin: 0; padding: 20px;" align="left">
        """
        # Card content
        self.heading2(title)
        for c in content:
            self.heading3(c["name"]).text(c["value"])
        # Card end
        self._email += """
                  </td>
                </tr>
              </tbody>
            </table>

                  </td>
                </tr>
              </tbody>
            </table>
            <table class="s-5 w-full" role="presentation" border="0" cellpadding="0" cellspacing="0" style="width: 100%;" width="100%">
              <tbody>
                <tr>
                  <td style="line-height: 20px; font-size: 20px; width: 100%; height: 20px; margin: 0;" align="left" width="100%" height="20">

                  </td>
                </tr>
              </tbody>
            </table>
        """
        if end == "\n":
            self._spacebelow()
        return self

    def _spacebelow(self) -> EmailNotify:
        self._email += """
            <table class="s-3 w-full" role="presentation" border="0" cellpadding="0" cellspacing="0" style="width: 100%;" width="100%">
              <tbody>
                <tr>
                  <td style="line-height: 12px; font-size: 12px; width: 100%; height: 12px; margin: 0;" align="left" width="100%" height="12">
                     
                  </td>
                </tr>
              </tbody>
            </table>
        """
        return self

    def bold(self, text) -> str:
        return f'<b>{text}</b>'

    def italic(self, text) -> str:
        return f'<i>{text}</i>'

    def __str__(self) -> str:
        return self._email

    def clean(self) -> EmailNotify:
      return EmailNotify()

    def send(self, subject: str,  email: str, preview: str):
        # End container
        self._email += """
                           </td>
                        </tr>
                      </tbody>
                    </table>
                    <!--[if (gte mso 9)|(IE)]>
                            </td>
                          </tr>
                        </tbody>
                      </table>
                    <![endif]-->
                  </td>
                </tr>
              </tbody>
            </table>
        """
        # End body
        self._email += """
              </td>
            </tr>
          </tbody>
        </table>
        <div id="force-encoding-to-utf-8" style="display: none;">&#10175;</div>
        </body>
        </html>
        """


        # Create message container - the correct MIME type is multipart/alternative.
        
        mailserver = smtplib.SMTP('exchange.ua.pt',25)
        mailserver.ehlo()
        mailserver.starttls()
        mailserver.login('deti-vuln-mon@ua.pt','eGdgtY56eF#bve8AxeFe')

        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = 'deti-vuln-mon@ua.pt'
        msg['To'] = email
        html = MIMEText(self._email, 'html')
        msg.attach(html)
        mailserver.sendmail('deti-vuln-mon@ua.pt',email,msg.as_string())
        
        mailserver.quit()
