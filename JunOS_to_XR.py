
from sys import argv
import re
import string

script, input_file = argv
def task(inFile):

    current_file = open(inFile, 'r')
    file = open("Jun-XR_Draft.log","w")
    Notes = open("READ_ME.log","w")
    
    
    ### Declare Lists ####
    da_list = []
    dp_list = []
    sa_list = []
    sp_list = []
    icmp_list = []
    options_list = []
    protocol_list=[]
    
    
    ### Declare Variables ####
    acl = "Dummy acl 123"
    remark = "Dummy Remark 123"
    sa = ""
    da = ""
    dummy_rmk = ""
    action = ""
    protocol = ""
    log = ""
    line_number =0
    w = ""
    ### Read the File ####
    for line in current_file:
        line_number = line_number + 1
        dummy_rmk = re.findall(r"(?<=term) (\b(?<!\*)[^\s\*]+)\b(?!\*)", line)
        dummy_acl = re.findall(r"(?<=inet filter) (\b(?<!\*)[^\s\*]+)\b(?!\*)", line)
    ### Write to file in case remarks have changed ###
    
        if (dummy_rmk != remark and remark != "Dummy Remark 123") or (dummy_acl != acl and acl != "Dummy acl 123"):
            file.write ("!\nipv4 access-list " + str(acl).strip("'[]") + "\n")
            file.write (" remark " + str(remark).strip("'[]") + "\n")
            if len(sa_list) == 0:
                sa_list.append(" any")
                Notes.write ("ACL: " + str(acl).strip("'[]") + " remark: " + str(remark).strip("'[]") + ". No source address was provided. 'Any' is used.\n")
            if len(da_list) == 0:
                da_list.append(" any")
                Notes.write ("ACL: " + str(acl).strip("'[]") + " remark: " + str(remark).strip("'[]") + ". No destination address was provided. 'Any' is used.\n")
            if len(sp_list) == 0:
                sp_list.append("")
            if len(dp_list) == 0:
                dp_list.append("")
            if len(icmp_list) == 0:
                icmp_list.append("")
            if len(protocol_list) == 0:
                protocol_list.append(" ipv4")
                Notes.write ("ACL: " + str(acl).strip("'[]") + " remark: " + str(remark).strip("'[]") + ". No protocol was provided. 'IPv4' is used.\n")
            if len(options_list) == 0:
                options_list.append("")
            if not log:
                log=""
            if action == "":
                Notes.write ("ACL: " + str(acl).strip("'[]") + " remark: " + str(remark).strip("'[]") + ". No permit or deny were found. Check this ACL.\n")
            for protocol in protocol_list:
                for sa in sa_list:
                    for da in da_list:
                        for sp in sp_list:
                            for dp in dp_list:
                                for icmp in icmp_list:
                                    for options in options_list:
                                        file.write ( " " + action + protocol + sa + sp + da + dp + icmp + options + str(log) + "\n")                            
            dp_list=[]
            sp_list=[]
            sa_list=[]
            da_list=[]
            icmp_list=[]
            log = ""
            protocol_list =[]
            options_list= []
            action = ""
    
    
    #### Get values from lines ###
        acl = re.findall(r"(?<=inet filter) (\b(?<!\*)[^\s\*]+)\b(?!\*)", line)
        da = re.findall(r"(?<=from destination-address )(\b\w*.*\b)", line)
        dp = re.findall(r"(?<=from destination-port )(\b\w*.*\b)", line)
        dpl = re.findall(r"(?<=from destination-prefix-list )(\b\w*.*\b)", line)
        dscp = re.findall(r"(?<=from dscp )(\b\w*.*\b)", line)
        icmp_code = re.findall(r"(?<=from icmp-code )(\b\w*.*\b)", line)
        icmp_type = re.findall(r"(?<=from icmp-type )(\b\w*.*\b)", line)
        fa = re.findall(r"(?<=from address )(\b\w*.*\b)", line)
        fpl = re.findall(r"(?<=from prefix-list )(\b\w*.*\b)", line)
        port = re.findall(r"(?<=from port )(\b\w*.*\b)", line)
        precedence = re.findall(r"(?<=from precedence )(\b\w*.*\b)", line)
        protocol = re.findall(r"(?<=from protocol )(\b\w*.*\b)", line)
        remark = re.findall(r"(?<=term) (\b(?<!\*)[^\s\*]+)\b(?!\*)", line)
        sa = re.findall(r"(?<=from source-address )(\b\w*.*\b)", line)
        sp = re.findall(r"(?<=from source-port )(\b\w*.*\b)", line)
        spl = re.findall(r"(?<=from source-prefix-list )(\b\w*.*\b)", line)
        ttl = re.findall(r"(?<=from ttl )(\b\w*.*\b)", line)
        log = re.search(r"(?<=then log)(\b\w*.*\b)", line)
    
    
    
    
    
        dpe = re.findall(r"(?<=from destination-port-except )(\b\w*.*\b)", line)
        dscp_ex = re.findall(r"(?<=from dscp-except )(\b\w*.*\b)", line)
        icmp_code_ex = re.findall(r"(?<=from icmp-code-except )(\b\w*.*\b)", line)
        icmp_type_ex = re.findall(r"(?<=from icmp-type-except )(\b\w*.*\b)", line)
        precedence_ex = re.findall(r"(?<=from precedence-except )(\b\w*.*\b)", line)
        protocol_ex = re.findall(r"(?<=from protocol-except )(\b\w*.*\b)", line)
        port_ex = re.findall(r"(?<=from port-except )(\b\w*.*\b)", line)
        spe = re.findall(r"(?<=from source-port-except )(\b\w*.*\b)", line)
        ttl_ex = re.findall(r"(?<=from ttl-except )(\b\w*.*\b)", line)
    
        
    ### Append values to lists ###
        if da:
            da_list.append(" " + str(da).strip("'[]"))
        if dp:
            dp = str(dp).strip("'[]")
            if ('-0' in dp) or ('-1' in dp) or ('-2' in dp) or ('-3' in dp) or ('-4' in dp) or ('-5' in dp) or ('-6' in dp) or ('-7' in dp) or ('-8' in dp) or ('-9' in dp):
                dp=dp.replace("-"," ")
                dp_list.append(" range " + str(dp).strip("'[]"))
            else:
                dp_list.append(" eq " + str(dp).strip("'[]"))
        if dpl:
            Notes.write ("line " + str(line_number) + ": Prefix-list keyworkd in JunOS is treated as net-group in XR, be sure it exists in your config.\n")
            da_list.append(" net-group " + str(dpl).strip("'[]"))
        if dscp:
            options_list.append(" dscp " + str(dscp).strip("'[]"))
        if icmp_code:
            icmp_list.append(" " + str(icmp_code).strip("'[]"))
        if icmp_type:
            icmp_list.append(" " + str(icmp_type).strip("'[]"))
        if fa:
            sa_list.append(" " + str(fa).strip("'[]"))
            Notes.write ("Line " + str(line_number) + ": JunOS treats 'From address' as either source or destination. This is not possible in XR and it's used as source. \n")
        if fpl:
            Notes.write ("Line " + str(line_number) + ": 'Prefix-list' keyword in JunOS is treated as net-group in XR, be sure it exists in your config.\n")
            Notes.write ("Line " + str(line_number) + ": JunOS treats 'From prefix-list' as either source or destination. This is not possible in XR and it's used as source.\n")
            sa_list.append(" net-group " + str(fpl).strip("'[]"))
        if port:
            port = str(port).strip("'[]")
            Notes.write ("Line " + str(line_number) + " " + ": Junos treats 'From port' as either source or destination. This is not possible in XR and it's used as source.\n")
            if ('-0' in port) or ('-1' in port) or ('-2' in port) or ('-3' in port) or ('-4' in port) or ('-5' in port) or ('-6' in port) or ('-7' in port) or ('-8' in port) or ('-9' in port):
                port=port.replace("-"," ")
                sp_list.append(" range " + str(port).strip("'[]"))
            else:
                sp_list.append(" eq " + str(port).strip("'[]"))
        if precedence:
            options_list.append(" precedence " + str(precedence).strip("'[]"))
        if protocol:
            protocol_list.append(" " + str(protocol).strip("'[]"))
        if sa:
            sa_list.append(" " + str(sa).strip("'[]"))
        if sp:
            sp = str(sp).strip("'[]")
            if ('-0' in sp) or ('-1' in sp) or ('-2' in sp) or ('-3' in sp) or ('-4' in sp) or ('-5' in sp) or ('-6' in sp) or ('-7' in sp) or ('-8' in sp) or ('-9' in sp):
                sp=sp.replace("-"," ")
                sp_list.append(" range " + str(sp).strip("'[]"))
            else:
                sp_list.append(" eq " + str(sp).strip("'[]"))
        if spl:
            Notes.write ("Line " + str(line_number) + ": 'Prefix-list' keyword in JunOS is treated as net-group in XR. Please create the net-group manually.\n")
            sa_list.append(" net-group " + str(spl).strip("'[]"))
        if ttl:
            if "-" in ttl:
                options_list.append(" ttl range " + str(ttl).strip("'[]"))
            else:
                options_list.append(" ttl eq " + str(ttl).strip("'[]"))
        if "from tcp-established" in line:
            options_list.append (" established ")
        if " then accept" in line:
            action = "permit"
        if " then drop" in line:
            action = "deny"
        if " then discard" in line:
            action = "deny"
        if log:
            log = "log"
    
    ### Exceptions ###
        if dpe:
            dpe = str(dpe).strip("'[]")
            if ('-0' in dpe) or ('-1' in dpe) or ('-2' in dpe) or ('-3' in dpe) or ('-4' in dpe) or ('-5' in dpe) or ('-6' in dpe) or ('-7' in dpe) or ('-8' in dpe) or ('-9' in dpe):
                dpe=dpe.replace("-"," ")
                dp_list.append(" -except range " + str(dpe).strip("'[]"))
                Notes.write ("ACL: " + str(acl).strip("'[]") + " remark: " + str(remark).strip("'[]") + ". Except-item is used, double check this rule and modify if needed. \n")
    #            dp_list.append(" any ")
            else:
                dp_list.append(" -except eq " + str(dpe).strip("'[]"))
                Notes.write ("ACL: " + str(acl).strip("'[]") + " remark: " + str(remark).strip("'[]") + ". Except-item is used, double check this rule and modify if needed.\n")
    #            dp_list.append(" any ")
        if dscp_ex:
            options_list.append(" -except dscp " + str(dscp_ex).strip("'[]"))
            Notes.write ("ACL: " + str(acl).strip("'[]") + " remark: " + str(remark).strip("'[]") + ". Except-item is used, double check this rule and modify if needed.\n")
    #        options_list.append(" any ")
        if icmp_code_ex:
            icmp_list.append(" -except " + str(icmp_code_ex).strip("'[]"))
            Notes.write ("ACL: " + str(acl).strip("'[]") + " remark: " + str(remark).strip("'[]") + ". Except-item is used, double check this rule and modify if needed.\n")
    #        icmp_list.append(" any ")
        if icmp_type_ex:
            icmp_list.append(" -except " + str(icmp_type_ex).strip("'[]"))
            Notes.write ("ACL: " + str(acl).strip("'[]") + " remark: " + str(remark).strip("'[]") + ". Except-item is used, double check this rule and modify if needed.\n")
    #        icmp_list.append(" any ")
        if precedence_ex:
            options_list.append(" -except precedence " + str(precedence_ex).strip("'[]"))
            Notes.write ("ACL: " + str(acl).strip("'[]") + " remark: " + str(remark).strip("'[]") + ". Except-item is used, double check this rule and modify if needed.\n")
    #        options_list.append(" any ")
        if port_ex:
            port_ex = str(port_ex).strip("'[]")
            Notes.write ("Line " + str(line_number) + ": Junos treats 'From port' as either source or destination. This is not possible in XR and it's used as source.\n")
            if ('-0' in port_ex) or ('-1' in port_ex) or ('-2' in port_ex) or ('-3' in port_ex) or ('-4' in port_ex) or ('-5' in port_ex) or ('-6' in port_ex) or ('-7' in port_ex) or ('-8' in port_ex) or ('-9' in port_ex):
                port_ex=port_ex.replace("-"," ")
                sp_list.append(" -except range " + str(port_ex).strip("'[]"))
                Notes.write ("ACL: " + str(acl).strip("'[]") + " remark: " + str(remark).strip("'[]")+ ". Except-item is used, double check this rule and modify if needed.\n")
    #            sp_list.append(" any ")
            else:
                sp_list.append(" -except eq " + str(port_ex).strip("'[]"))
    #            sp_list.append(" any ")
        if protocol_ex:
            protocol_list.append(" " + str(protocol_ex).strip("'[]"))
            Notes.write ("ACL: " + str(acl).strip("'[]") + " remark: " + str(remark).strip("'[]") + ". Except-item is used, double check this rule and modify if needed.\n")
    #        protocol_list.append(" any ")
        if spe:
            spe = str(spe).strip("'[]")
            if ('-0' in spe) or ('-1' in spe) or ('-2' in spe) or ('-3' in spe) or ('-4' in spe) or ('-5' in spe) or ('-6' in spe) or ('-7' in spe) or ('-8' in spe) or ('-9' in spe):
                spe=spe.replace("-"," ")
                sp_list.append(" -except range " + str(spe).strip("'[]"))
                Notes.write ("ACL: " + str(acl).strip("'[]") + " remark: " + str(remark).strip("'[]") + ". Except-item is used, double check this rule and modify if needed.\n")
    #            sp_list.append(" any ")
            else:
                sp_list.append(" -except eq " + str(spe).strip("'[]"))
                Notes.write ("ACL: " + str(acl).strip("'[]") + " remark: " + str(remark).strip("'[]") + ". Except-item is used, double check this rule and modify if needed.\n")
    #            sp_list.append(" any ")
        if ttl_ex:
            if "-" in ttl:
                options_list.append(" -except ttl range " + str(ttl_ex).strip("'[]"))
                Notes.write ("ACL: " + str(acl).strip("'[]") + " remark: " + str(remark).strip("'[]") + ". Except-item is used, double check this rule and modify if needed.\n")
    #            optoins_list.append(" any ")
            else:
                options_list.append(" -except eq " + str(ttl_ex).strip("'[]"))
                Notes.write ("ACL: " + str(acl).strip("'[]") + " remark: " + str(remark).strip("'[]") + ". Except-item is used, double check this rule and modify if needed.\n")
    #            options_list.append(" any ")
    
    #### Not Supported keyworkdsf
        if "interface-set" in line:
            Notes.write ("Line " + str(line_number) + ": 'interface-set' not supported in XR.\n")
        if "tcp-initial" in line:
            Notes.write ("Line " + str(line_number) + ": 'tcp-initial' not supported in XR.\n")
        if "first-fragment" in line:
            Notes.write ("Line " + str(line_number) + ": 'first-fragment' not supported in XR.\n")
        if "fragment-flags" in line:
            Notes.write ("Line " + str(line_number) + ": 'fragment-flags' not supported in XR.\n")
        if "fragment-offset" in line:
            Notes.write ("Line " + str(line_number) + ": 'fragment-offset' not supported in XR.\n")
        if "fragment-offset-exc" in line:
            Notes.write ("Line " + str(line_number) + ": 'fragment-offset-exc' not supported in XR.\n")
        if "interface-group" in line:
            Notes.write ("Line " + str(line_number) + ": 'interface-group' not supported in XR.\n")
        if "interface-group-except" in line:
            Notes.write ("Line " + str(line_number) + ": 'interface-group-except' not supported in XR.\n")
        if "is-fragment" in line:
            Notes.write ("Line " + str(line_number) + ": 'is-fragment' not supported in XR.\n")
        if "service-filter-hit" in line:
            Notes.write ("Line " + str(line_number) + ": 'service-filter-hit' not supported in XR.\n")
        if "from interface" in line:
            Notes.write ("Line " + str(line_number) + ": 'interface' not supported in XR.\n")
        if "apply-groups" in line:
            Notes.write ("Line " + str(line_number) + ": 'apply-groups' not supported in XR.\n")
        if "apply-groups-except" in line:
            Notes.write ("Line " + str(line_number) + ": 'apply-groups-except' not supported in XR.\n")
        if "packet-length" in line:
            Notes.write ("Line " + str(line_number) + ": 'packet-length' not supported in XR.\n")
        if "packet-length-except" in line:
            Notes.write ("Line " + str(line_number) + ": 'packet-length-except' not supported in XR.\n")
        if "forwarding-class" in line:
            Notes.write ("Line " + str(line_number) + ": 'forwarding-class' not supported in XR.\n")
        if "forwarding-class-except" in line:
            Notes.write ("Line " + str(line_number) + ": 'forwarding-class-except' not supported in XR.\n")
        if "tcp-flgas" in line:
            Notes.write ("Line " + str(line_number) + ": 'tcp-flgas' not supported in XR.\n")
        if "tcp-flgas-except" in line:
            Notes.write ("Line " + str(line_number) + ": 'tcp-flgas-except' not supported in XR.\n")    
    
    #### Last Line ##############
    
        if (line[-1]) != "\n":
            file.write ("!\nipv4 access-list " + str(acl).strip("'[]") + "\n")
            file.write (" remark " + str(remark).strip("'[]") + "\n")
            if len(sa_list) == 0:
                sa_list.append(" any")
                Notes.write ("ACL: " + str(acl).strip("'[]") + " remark: " + str(remark).strip("'[]") + ". No source address was provided. 'Any' is used.\n")
            if len(da_list) == 0:
                da_list.append(" any")
                Notes.write ("ACL: " + str(acl).strip("'[]") + " remark: " + str(remark).strip("'[]") + ". No destination address was provided. 'Any' is used.\n")
            if len(sp_list) == 0:
                sp_list.append("")
            if len(dp_list) == 0:
                dp_list.append("")
            if len(icmp_list) == 0:
                icmp_list.append("")
            if len(protocol_list) == 0:
                protocol_list.append(" ipv4")
                Notes.write ("ACL: " + str(acl).strip("'[]") + " remark: " + str(remark).strip("'[]") + ". No protocol was provided. 'IPv4' is used.\n")
            if len(options_list) == 0:
                options_list.append("")
            if not log:
                log=""
            if action == "":
                Notes.write ("ACL: " + str(acl).strip("'[]") + " remark: " + str(remark).strip("'[]") + ". No permit or deny were found. Check this ACL.\n")
            for protocol in protocol_list:
                for sa in sa_list:
                    for da in da_list:
                        for sp in sp_list:
                            for dp in dp_list:
                                for icmp in icmp_list:
                                    for options in options_list:
                                        file.write ( " " + action + protocol + sa + sp + da + dp + icmp + options + str(log) + "\n")                            
            dp_list=[]
            sp_list=[]
            sa_list=[]
            da_list=[]
            icmp_list=[]
            log = ""
            protocol_list =[]
            options_list= []
            action=""
    
    
                    
    #print ("your script has been generated.")
    file.close()
    
    input = open("Jun-XR_Draft.log",'r')
    lst=[]
    word = "-except"
    for line in input:
        if word in line:
            line = line.replace(word,'')
            lst.append(" exclude-item" + str(line).strip("\n"))
        else:
            lst.append(str(line).strip("\n"))
    input.close()
    
    
    output = open("Jun-XR_Final.log","w")
    for line in lst:
        output.write(line + "\n")
        #print(line)
    output.close()
    
    print ("Conversion complete, download outputs from the folder on top of this page. Please read the READ-ME file")

if __name__ == "__main__":
    task(input_file)