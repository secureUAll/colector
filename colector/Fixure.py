from typing import Counter
import xml.etree.ElementTree as ET
import json

"""class Fixure():
    def __init__(self, message):
        self.message = message
        self.retorno = {}

    def fix(self):
        outputs = self.message["output"]

        for out in outputs:
            palavras = out.split()
            if len(palavras)>0 and "CVE-" in palavras[0]:
                cve = palavras[0].replace("[", "").replace("]", "")
                print(cve)
                #self.getFixes(cve)

        return self.retorno

    def getFixes(self, cve):
        pass


f = Fixure({"output": [
    "VulDB - https://vuldb.com:",
    "[130671] gsi-openssh-server 7.9p1 on Fedora /etc/gsissh/sshd_config weak authentication",
    "[130371] OpenSSH 7.9 scp Man-in-the-Middle directory traversal",
    "[130370] OpenSSH 7.9 Man-in-the-Middle spoofing",
    "MITRE CVE - https://cve.mitre.org:",
    "[CVE-1999-0661] A system is running a version of software that was replaced with a Trojan Horse at one of its distribution points, such as (1) TCP Wrappers 7.6, (2) util-linux 2.9g, (3) wuarchive ftpd (wuftpd) 2.2 and 2.1f, (4) IRC client (ircII) ircII 2.2.9, (5) OpenSSH 3.4p1, or (6) Sendmail 8.12.6.",
    "[CVE-2010-4755] The (1) remote_glob function in sftp-glob.c and the (2) process_put function in sftp.c in OpenSSH 5.8 and earlier, as used in FreeBSD 7.3 and 8.1, NetBSD 5.0.2, OpenBSD 4.7, and other products, allow remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames, as demonstrated by glob expressions in SSH_FXP_STAT requests to an sftp daemon, a different vulnerability than CVE-2010-2632.",
    ""
]})

f.fix()
"""

def throughCode(root, depth):
    if len(root)==0:
        tabs=""
        body=""
        for x in range (0, depth):
            tabs+="/tab/"
        if root.tag=="{http://www.w3.org/1999/xhtml}br":
            body="/newline/"
        else:
            #body=ET.tostring(root).decode("latin")
            body=root.text
        return tabs+body
    
    retorno=""

    # CHECK IF ALL INDIVIDUAL ELEMENTS ARE <BR>
    child_no=len(root)
    br_no=0
    for child in root:
        if child.tag=="{http://www.w3.org/1999/xhtml}br":
            br_no+=1
    if child_no==br_no:
        for x in root:
            retorno+=ET.tostring(x).decode("latin").replace("<html:br xmlns:html=\"http://www.w3.org/1999/xhtml\" />", "/newline/").replace("\n                  ", "")
    else:
        for child in root:
            retorno+=throughCode(child, depth+1)
    
    return retorno



def readCWE(filename):
    tree = ET.parse(filename)
    root = tree.getroot()
    rel_cve_fix={}
    for child in root:
        if child.tag == '{http://cwe.mitre.org/cwe-6}Weaknesses':
            weeknesses = child.findall("{http://cwe.mitre.org/cwe-6}Weakness")
            for wk in weeknesses:
                # MITIGATIONS
                temp_mitigations=[]
                pm = wk.find("{http://cwe.mitre.org/cwe-6}Potential_Mitigations")
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
                        strategy=""

                    temp_mitigations.append({
                        "phase":phase,
                        "description":desc,
                        "effectiveness":effectiveness,
                        "effectiveness_notes":effectiveness_notes,
                        "strategy":strategy
                    })
                
                # DEMONSTRATIVE EXAMPLES
                demonstrative_examples=wk.find("{http://cwe.mitre.org/cwe-6}Demonstrative_Examples")
                temp_demonstratice_examples=[]
                for de in demonstrative_examples:
                    codigo={}
                    for child in de:
                        if child.tag=="{http://cwe.mitre.org/cwe-6}Intro_Text":
                            codigo["title"]=child.text
                        if child.tag=="{http://cwe.mitre.org/cwe-6}Example_Code":
                            codigo["code_"+child.attrib["Nature"]]=str(throughCode(child, 0))
                    
                    temp_demonstratice_examples.append(codigo)
                    #print(json.dumps(codigo))
                    #print(temp_demonstratice_examples)

                # CVES
                observed_examples = wk.find("{http://cwe.mitre.org/cwe-6}Observed_Examples")

                for oe in observed_examples.findall("{http://cwe.mitre.org/cwe-6}Observed_Example"):
                    cve=oe.find("{http://cwe.mitre.org/cwe-6}Reference").text
                    if cve in rel_cve_fix:
                        rel_cve_fix[cve]["mitigations"]+=temp_mitigations
                        rel_cve_fix[cve]["code_exmaples"]+=temp_demonstratice_examples
                    else:
                        rel_cve_fix[cve]={"mitigations":temp_mitigations, "code_exmaples":temp_demonstratice_examples}
    formato_json = json.dumps(rel_cve_fix)

readCWE('cwec.xml')