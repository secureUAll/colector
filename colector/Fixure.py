from typing import Counter
import xml.etree.ElementTree as ET
import json
from bs4 import BeautifulSoup
from urllib.request import Request, urlopen
import re


class Fixure():
    def __init__(self, message):
        self.message = message
        self.retorno = {}

    def fix(self):
        outputs = self.message["output"]

        f=open("cve_suggestion.json", "rb")
        json_text=f.read()

        self.rel_cve_suggestion=json.loads(json_text)

        self.retorno={}
        for out in outputs:
            palavras = out.split()
            if len(palavras) > 0 and "CVE-" in palavras[0]:
                cve = palavras[0].replace("[", "").replace("]", "")
                self.retorno[cve]=self.getFixes(cve)

        return self.retorno

    def getFixes(self, cve):
        if cve in self.rel_cve_suggestion:
            return self.rel_cve_suggestion[cve]
        else:
            return {}

    def throughCode(self, root, depth):
        if len(root) == 0:
            tabs = ""
            body = ""
            for x in range(0, depth):
                tabs += "<div style='padding-left: 20px;'></div>"
            if root.tag == "{http://www.w3.org/1999/xhtml}br":
                body = "<br>"
            else:
                # body=ET.tostring(root).decode("latin")
                if root.text is not None:
                    body = root.text
                else:
                    body=""
            return tabs+body
        
        retorno = ""

        # CHECK IF ALL INDIVIDUAL ELEMENTS ARE <BR>
        child_no = len(root)
        br_no = 0
        for child in root:
            if child.tag == "{http://www.w3.org/1999/xhtml}br":
                br_no += 1
        if child_no == br_no:
            for x in root:
                retorno += ET.tostring(x).decode("latin").replace(
                    "<html:br xmlns:html=\"http://www.w3.org/1999/xhtml\" />", "<br>").replace("\n", "").replace("  ", "")
        else:
            for child in root:
                retorno += self.throughCode(child, depth+1)
        
        #retorno=ET.tostring(root, encoding='unicode')
        return retorno


    def readCWE(self, filename="cwec.xml"):
        tree = ET.parse(filename)
        root = tree.getroot()
        rel_cve_fix = {}
        for child in root:
            if child.tag == '{http://cwe.mitre.org/cwe-6}Weaknesses':
                weeknesses = child.findall("{http://cwe.mitre.org/cwe-6}Weakness")
                for wk in weeknesses:
                    print(wk.attrib["ID"])
                    # MITIGATIONS
                    temp_mitigations = []
                    pm = wk.find("{http://cwe.mitre.org/cwe-6}Potential_Mitigations")
                    if pm is not None:
                        mitigations = pm.findall("{http://cwe.mitre.org/cwe-6}Mitigation")
                        for mt in mitigations:
                            phases = mt.findall("{http://cwe.mitre.org/cwe-6}Phase")
                            description = mt.find(
                                "{http://cwe.mitre.org/cwe-6}Description")

                            if phases is not []:
                                text = ""
                                c = 0
                                for x in phases:
                                    c += 1
                                    text += x.text
                                    if c < len(phases):
                                        text += ", "
                                phase = text
                            else:
                                phase = ""

                            if len(description.findall("{http://www.w3.org/1999/xhtml}p")) > 0:
                                text = ""
                                for x in description:
                                    text += x.text
                                desc = text
                            else:
                                desc = description.text

                            if mt.find("{http://cwe.mitre.org/cwe-6}Effectiveness") is not None:
                                effectiveness = mt.find(
                                    "{http://cwe.mitre.org/cwe-6}Effectiveness").text
                            else:
                                effectiveness = ""

                            if mt.find("{http://cwe.mitre.org/cwe-6}Effectiveness_Notes") is not None:
                                effectiveness_notes = mt.find(
                                    "{http://cwe.mitre.org/cwe-6}Effectiveness_Notes").text
                            else:
                                effectiveness_notes = ""

                            if mt.find("{http://cwe.mitre.org/cwe-6}Strategy") is not None:
                                strategy = mt.find(
                                    "{http://cwe.mitre.org/cwe-6}Strategy").text
                            else:
                                strategy = ""

                            temp_mitigations.append({
                                "phase": phase,
                                "description": desc,
                                "effectiveness": effectiveness,
                                "effectiveness_notes": effectiveness_notes,
                                "strategy": strategy
                            })

                    # DEMONSTRATIVE EXAMPLES
                    demonstrative_examples = wk.find(
                        "{http://cwe.mitre.org/cwe-6}Demonstrative_Examples")
                    temp_demonstratice_examples = []

                    if demonstrative_examples is not None:
                        for de in demonstrative_examples:
                            codigo = {}
                            for child in de:
                                if child.tag == "{http://cwe.mitre.org/cwe-6}Intro_Text":
                                    codigo["title"] = child.text
                                if child.tag == "{http://cwe.mitre.org/cwe-6}Example_Code":
                                    codigo["code_"+child.attrib["Nature"]] = str(self.throughCode(child, 0))

                            temp_demonstratice_examples.append(codigo)
                            # print(json.dumps(codigo))
                            # print(temp_demonstratice_examples)

                    # CVES
                    observed_examples = wk.find(
                        "{http://cwe.mitre.org/cwe-6}Observed_Examples")
                    if observed_examples is not None:
                        for oe in observed_examples.findall("{http://cwe.mitre.org/cwe-6}Observed_Example"):
                            cve = oe.find("{http://cwe.mitre.org/cwe-6}Reference").text
                            
                            if cve in rel_cve_fix:
                                rel_cve_fix[cve]["mitigations"] += [x for x in temp_mitigations if all([x["description"]!=y["description"] and x["strategy"]!=y["strategy"] for y in rel_cve_fix[cve]["mitigations"]])]
                                rel_cve_fix[cve]["code_exmaples"] += [x for x in temp_demonstratice_examples if all([x["title"]!=y["title"] for y in rel_cve_fix[cve]["code_exmaples"]])]
                            else:
                                rel_cve_fix[cve] = {
                                    "cvss":self.getCVSS(cve),"mitigations": temp_mitigations, "code_exmaples": temp_demonstratice_examples}
        formato_json = json.dumps(rel_cve_fix)
        f = open("cve_suggestion.json", "wb")
        f.write(formato_json.encode("latin"))
        f.close()

    def printCode(self):
        # just for test purposes
        code = self.retorno['CVE-2009-2874']['code_exmaples'][0]['code_bad'].replace("/tab/", "\t").replace("/newline/","\n")
        print(f'{code}')
        pass

    def getCVSS(self, cve):
        req = Request("https://www.cvedetails.com/cve/"+cve+"/", headers={'User-Agent': 'Mozilla/5.0'})
        fp = urlopen(req)
   
        mybytes = fp.read()

        html = mybytes.decode("utf8")
        fp.close()

        soup=BeautifulSoup(html, "html.parser")
        l=soup.find_all("div", class_="cvssbox")

        if len(l)==0:
            cvss='-'
        else:
            div_cvss=l[0]
            cvss=re.findall(r">.*<", str(div_cvss))[0].replace("<","").replace(">", "")
        
        return cvss



f = Fixure({"output": [
    "VulDB - https://vuldb.com:",
    "[130671] gsi-openssh-server 7.9p1 on Fedora /etc/gsissh/sshd_config weak authentication",
    "[130371] OpenSSH 7.9 scp Man-in-the-Middle directory traversal",
    "[130370] OpenSSH 7.9 Man-in-the-Middle spoofing",
    "MITRE CVE - https://cve.mitre.org:",
    "[CVE-2009-2874] A system is running a version of software that was replaced with a Trojan Horse at one of its distribution points, such as (1) TCP Wrappers 7.6, (2) util-linux 2.9g, (3) wuarchive ftpd (wuftpd) 2.2 and 2.1f, (4) IRC client (ircII) ircII 2.2.9, (5) OpenSSH 3.4p1, or (6) Sendmail 8.12.6.",
    "[CVE-2010-4755] The (1) remote_glob function in sftp-glob.c and the (2) process_put function in sftp.c in OpenSSH 5.8 and earlier, as used in FreeBSD 7.3 and 8.1, NetBSD 5.0.2, OpenBSD 4.7, and other products, allow remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames, as demonstrated by glob expressions in SSH_FXP_STAT requests to an sftp daemon, a different vulnerability than CVE-2010-2632.",
    ""
]})

#f.readCWE("cwec_v4.4.xml")
f.readCWE()
f.fix()
#f.printCode()
#f.getCVSS("CVE-2014-3852")