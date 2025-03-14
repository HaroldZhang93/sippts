from sippts.lib.color import Color


class UiTools:
    def __init__(self):
        pass
    
    def set_option_scan(mod, param, value, run, log):
        c = Color()
        supported_protos = ["UDP", "TCP", "TLS"]
        supported_methods = ["OPTIONS", "REGISTER", "INVITE"]

        ok = True

        if param == "ip":
            if run == False:
                mod.ip = value
            else:
                value = mod.ip
        elif param == "file":
            if run == False:
                mod.file = value
            else:
                value = mod.file
        elif param == "rport":
            if run == False:
                mod.rport = value
            else:
                value = mod.rport
        elif param == "proto":
            if run == False:
                value = value.upper()
                if value not in supported_protos:
                    if value == "ALL":
                        mod.proto = "UDP|TCP|TLS"
                    else:
                        if log == True:
                            print(
                                f"{c.WHITE}Protocol {c.BRED}{value} {c.WHITE}is not supported\n"
                            )
                        ok = False
                else:
                    mod.proto = value
            else:
                value = mod.proto
        elif param == "proxy":
            if run == False:
                mod.proxy = value
            else:
                value = mod.proxy
        elif param == "method":
            if run == False:
                value = value.upper()
                if value not in supported_methods:
                    if log == True:
                        print(
                            f"{c.WHITE}Method {c.BRED}{value} {c.WHITE}is not supported\n"
                        )
                    ok = False
                else:
                    mod.method = value
            else:
                value = mod.method
        elif param == "domain":
            if run == False:
                mod.domain = value
            else:
                value = mod.domain
        elif param == "contact_domain":
            if run == False:
                mod.contact_domain = value
            else:
                value = mod.contact_domain
        elif param == "from_name":
            if run == False:
                mod.from_name = value
            else:
                value = mod.from_name
        elif param == "from_user":
            if run == False:
                mod.from_user = value
            else:
                value = mod.from_user
        elif param == "from_domain":
            if run == False:
                mod.from_domain = value
            else:
                value = mod.from_domain
        elif param == "to_name":
            if run == False:
                mod.to_name = value
            else:
                value = mod.to_name
        elif param == "to_user":
            if run == False:
                mod.to_user = value
            else:
                value = mod.to_user
        elif param == "to_domain":
            if run == False:
                mod.to_domain = value
            else:
                value = mod.to_domain
        elif param == "ua":
            if run == False:
                mod.user_agent = value
            else:
                value = mod.user_agent
        elif param == "ppi":
            if run == False:
                mod.ppi = value
            else:
                value = mod.ppi
        elif param == "pai":
            if run == False:
                mod.pai = value
            else:
                value = mod.pai
        elif param == "verbose":
            if run == False:
                if value != "0" and value != "1" and value != "2":
                    if log == True:
                        print(f"{c.WHITE}Value {c.BRED}{value} {c.WHITE}is not valid\n")
                    ok = False
                else:
                    mod.verbose = value
            else:
                value = mod.verbose
        elif param == "output_file":
            if run == False:
                mod.ofile = value
            else:
                value = mod.ofile
        elif param == "output_ip_file":
            if run == False:
                mod.oifile = value
            else:
                value = mod.oifile
        elif param == "cve":
            if run == False:
                mod.cve = value
            else:
                value = mod.cve
        elif param == "threads":
            if run == False:
                mod.threads = value
            else:
                value = mod.threads
        elif param == "timeout":
            if run == False:
                mod.timeout = int(value)
            else:
                value = mod.timeout
        elif param == "ping":
            if run == False:
                if value.lower() != "true" and value.lower() != "false":
                    if log == True:
                        print(f"{c.WHITE}Value {c.BRED}{value} {c.WHITE}is not valid\n")
                    ok = False
                else:
                    if value.lower() == "true":
                        mod.ping = True
                    else:
                        mod.ping = False
            else:
                value = mod.ping
        elif param == "fp":
            if run == False:
                if value.lower() != "true" and value.lower() != "false":
                    if log == True:
                        print(f"{c.WHITE}Value {c.BRED}{value} {c.WHITE}is not valid\n")
                    ok = False
                else:
                    if value.lower() == "true":
                        mod.fp = True
                    else:
                        mod.fp = False
            else:
                value = mod.fp
        elif param == "random":
            if run == False:
                if value.lower() != "true" and value.lower() != "false":
                    if log == True:
                        print(f"{c.WHITE}Value {c.BRED}{value} {c.WHITE}is not valid\n")
                    ok = False
                else:
                    if value.lower() == "true":
                        mod.random = True
                    else:
                        mod.random = False
            else:
                value = mod.random
        elif param == "local_ip":
            if run == False:
                mod.localip = value
            else:
                value = mod.localip
        else:
            if log == True:
                print(f"{c.WHITE}Wrong option: {c.BRED}{param}{c.WHITE}")
            ok = False

        if run == False and ok == True:
            if log == True:
                print(f"{c.GREEN}\n{param}{c.WHITE} -> {c.YELLOW}{value}{c.WHITE}\n")

        return value
    
    
    def set_option_exten(mod, param, value, run, log):
        c = Color()
        supported_protos = ["UDP", "TCP", "TLS"]
        supported_methods = ["OPTIONS", "REGISTER", "INVITE"]

        ok = True

        if param == "ip":
            if run == False:
                mod.ip = value
            else:
                value = mod.ip
        elif param == "rport":
            if run == False:
                mod.rport = value
            else:
                value = mod.rport
        elif param == "exten":
            if run == False:
                mod.exten = value
            else:
                value = mod.exten
        elif param == "prefix":
            if run == False:
                mod.prefix = value
            else:
                value = mod.prefix
        elif param == "proto":
            if run == False:
                value = value.upper()
                if value not in supported_protos:
                    if value == "ALL":
                        mod.proto = "UDP|TCP|TLS"
                    else:
                        if log == True:
                            print(
                                f"{c.WHITE}Protocol {c.BRED}{value} {c.WHITE}is not supported\n"
                            )
                        ok = False
                else:
                    mod.proto = value
            else:
                value = mod.proto
        elif param == "proxy":
            if run == False:
                mod.proxy = value
            else:
                value = mod.proxy
        elif param == "method":
            if run == False:
                value = value.upper()
                if value not in supported_methods:
                    if log == True:
                        print(
                            f"{c.WHITE}Method {c.BRED}{value} {c.WHITE}is not supported\n"
                        )
                    ok = False
                else:
                    mod.method = value
            else:
                value = mod.method
        elif param == "domain":
            if run == False:
                mod.domain = value
            else:
                value = mod.domain
        elif param == "contact_domain":
            if run == False:
                mod.contact_domain = value
            else:
                value = mod.contact_domain
        elif param == "from_user":
            if run == False:
                mod.from_user = value
            else:
                value = mod.from_user
        elif param == "ua":
            if run == False:
                mod.user_agent = value
            else:
                value = mod.user_agent
        elif param == "verbose":
            if run == False:
                if value != "0" and value != "1" and value != "2":
                    if log == True:
                        print(f"{c.WHITE}Value {c.BRED}{value} {c.WHITE}is not valid\n")
                    ok = False
                else:
                    mod.verbose = value
            else:
                value = mod.verbose
        elif param == "output_file":
            if run == False:
                mod.ofile = value
            else:
                value = mod.ofile
        elif param == "filter":
            if run == False:
                mod.filter = value
            else:
                value = mod.filter
        elif param == "threads":
            if run == False:
                mod.threads = value
            else:
                value = mod.threads
        elif param == "timeout":
            if run == False:
                mod.timeout = int(value)
            else:
                value = mod.timeout
        else:
            if log == True:
                print(f"{c.WHITE}Wrong option: {c.BRED}{param}{c.WHITE}")
            ok = False

        if run == False and ok == True:
            if log == True:
                print(f"{c.GREEN}\n{param}{c.WHITE} -> {c.YELLOW}{value}{c.WHITE}\n")

        return value
    

    def set_option_rcrack(mod, param, value, run, log):
        c = Color()
        supported_protos = ["UDP", "TCP", "TLS"]

        ok = True

        if param == "ip":
            if run == False:
                mod.ip = value
            else:
                value = mod.ip
        elif param == "rport":
            if run == False:
                mod.rport = value
            else:
                value = mod.rport
        elif param == "exten":
            if run == False:
                mod.exten = value
            else:
                value = mod.exten
        elif param == "auth_user":
            if run == False:
                mod.authuser = value
            else:
                value = mod.authuser
        elif param == "prefix":
            if run == False:
                mod.prefix = value
            else:
                value = mod.prefix
        elif param == "len":
            if run == False:
                mod.ext_len = value
            else:
                value = mod.ext_len
        elif param == "wordlist":
            if run == False:
                mod.wordlist = value
            else:
                value = mod.wordlist
        elif param == "proto":
            if run == False:
                value = value.upper()
                if value not in supported_protos:
                    if value == "ALL":
                        mod.proto = "UDP|TCP|TLS"
                    else:
                        if log == True:
                            print(
                                f"{c.WHITE}Protocol {c.BRED}{value} {c.WHITE}is not supported\n"
                            )
                        ok = False
                else:
                    mod.proto = value
            else:
                value = mod.proto
        elif param == "proxy":
            if run == False:
                mod.proxy = value
            else:
                value = mod.proxy
        elif param == "domain":
            if run == False:
                mod.domain = value
            else:
                value = mod.domain
        elif param == "contact_domain":
            if run == False:
                mod.contact_domain = value
            else:
                value = mod.contact_domain
        elif param == "ua":
            if run == False:
                mod.user_agent = value
            else:
                value = mod.user_agent
        elif param == "verbose":
            if run == False:
                if value != "0" and value != "1":
                    if log == True:
                        print(f"{c.WHITE}Value {c.BRED}{value} {c.WHITE}is not valid\n")
                    ok = False
                else:
                    mod.verbose = value
            else:
                value = mod.verbose
        elif param == "threads":
            if run == False:
                mod.threads = int(value)
            else:
                value = mod.threads
        elif param == "timeout":
            if run == False:
                mod.timeout = int(value)
            else:
                value = mod.timeout
        else:
            if log == True:
                print(f"{c.WHITE}Wrong option: {c.BRED}{param}{c.WHITE}")
            ok = False

        if run == False and ok == True:
            if log == True:
                print(f"{c.GREEN}\n{param}{c.WHITE} -> {c.YELLOW}{value}{c.WHITE}\n")

        return value
    
    
    def set_option_dump(mod, param, value, run, log):
        c = Color()
        ok = True

        if param == "file":
            if run == False:
                mod.file = value
            else:
                value = mod.file
        elif param == "output_file":
            if run == False:
                mod.ofile = value
            else:
                value = mod.ofile
        else:
            if log == True:
                print(f"{c.WHITE}Wrong option: {c.BRED}{param}{c.WHITE}")
            ok = False

        if run == False and ok == True:
            if log == True:
                print(f"{c.GREEN}\n{param}{c.WHITE} -> {c.YELLOW}{value}{c.WHITE}\n")

        return value
    
    def set_option_dcrack(mod, param, value, run, log):
        c = Color()
        ok = True

        if param == "file":
            if run == False:
                mod.file = value
            else:
                value = mod.file
        elif param == "wordlist":
            if run == False:
                mod.wordlist = value
                if mod.wordlist != "":
                    mod.bruteforce = 0
            else:
                value = mod.wordlist
        elif param == "bruteforce":
            if run == False:
                mod.bruteforce = int(value)
            else:
                value = mod.bruteforce
        elif param == "charset":
            if run == False:
                mod.charset = value
            else:
                value = mod.charset
        elif param == "min":
            if run == False:
                mod.min = int(value)
            else:
                value = mod.min
        elif param == "max":
            if run == False:
                mod.max = int(value)
            else:
                value = mod.max
        elif param == "verbose":
            if run == False:
                if value != "0" and value != "1":
                    if log == True:
                        print(f"{c.WHITE}Value {c.BRED}{value} {c.WHITE}is not valid\n")
                    ok = False
                else:
                    mod.verbose = value
            else:
                value = mod.verbose
        elif param == "threads":
            if run == False:
                mod.threads = int(value)
            else:
                value = mod.threads
        elif param == "prefix":
            if run == False:
                mod.prefix = value
            else:
                value = mod.prefix
        elif param == "suffix":
            if run == False:
                mod.suffix = value
            else:
                value = mod.suffix
        elif param == "username":
            if run == False:
                mod.username = value
            else:
                value = mod.username    
        else:
            if log == True:
                print(f"{c.WHITE}Wrong option: {c.BRED}{param}{c.WHITE}")
            ok = False

        if run == False and ok == True:
            if log == True:
                print(f"{c.GREEN}\n{param}{c.WHITE} -> {c.YELLOW}{value}{c.WHITE}\n")

        return value
    
    
    def set_option_flood(mod, param, value, run, log):
        c = Color()
        supported_protos = ["UDP", "TCP", "TLS"]
        supported_methods = ["OPTIONS", "REGISTER", "INVITE"]

        ok = True

        if param == "ip":
            if run == False:
                mod.ip = value
            else:
                value = mod.ip
        elif param == "rport":
            if run == False:
                mod.rport = value
            else:
                value = mod.rport
        elif param == "proto":
            if run == False:
                value = value.upper()
                if value not in supported_protos:
                    if value == "ALL":
                        mod.proto = "UDP|TCP|TLS"
                    else:
                        if log == True:
                            print(
                                f"{c.WHITE}Protocol {c.BRED}{value} {c.WHITE}is not supported\n"
                            )
                        ok = False
                else:
                    mod.proto = value
            else:
                value = mod.proto
        elif param == "method":
            if run == False:
                value = value.upper()
                if value not in supported_methods:
                    if log == True:
                        print(
                            f"{c.WHITE}Method {c.BRED}{value} {c.WHITE}is not supported\n"
                        )
                    ok = False
                else:
                    mod.method = value
            else:
                value = mod.method
        elif param == "domain":
            if run == False:
                mod.domain = value
            else:
                value = mod.domain
        elif param == "contact_domain":
            if run == False:
                mod.contact_domain = value
            else:
                value = mod.contact_domain
        elif param == "from_name":
            if run == False:
                mod.from_name = value
            else:
                value = mod.from_name
        elif param == "from_user":
            if run == False:
                mod.from_user = value
            else:
                value = mod.from_user
        elif param == "from_domain":
            if run == False:
                mod.from_domain = value
            else:
                value = self.mod.from_domain
        elif param == "to_name":
            if run == False:
                mod.to_name = value
            else:
                value = mod.to_name
        elif param == "to_user":
            if run == False:
                mod.to_user = value
            else:
                value = mod.to_user
        elif param == "to_domain":
            if run == False:
                mod.to_domain = value
            else:
                value = mod.to_domain
        elif param == "ua":
            if run == False:
                mod.user_agent = value
            else:
                value = mod.user_agent
        elif param == "digest":
            if run == False:
                mod.digest = value
            else:
                value = mod.digest
        elif param == "bad":
            if run == False:
                mod.bad = value
            else:
                value = mod.bad
        elif param == "charset":
            if run == False:
                mod.alphabet = value
            else:
                value = mod.alphabet
        elif param == "max":
            if run == False:
                mod.max = int(value)
            else:
                value = mod.max
        elif param == "min":
            if run == False:
                mod.min = int(value)
            else:
                value = mod.min
        elif param == "requests":
            if run == False:
                mod.number = int(value)
            else:
                value = mod.number
        elif param == "threads":
            if run == False:
                mod.nthreads = int(value)
            else:
                value = mod.nthreads
        elif param == "verbose":
            if run == False:
                if value != "0" and value != "1":
                    if log == True:
                        print(f"{c.WHITE}Value {c.BRED}{value} {c.WHITE}is not valid\n")
                    ok = False
                else:
                    mod.verbose = value
            else:
                value = mod.verbose
        elif param == "proxy":
            if run == False:
                mod.proxy = value
            else:
                value = mod.proxy
        else:
            if log == True:
                print(f"{c.WHITE}Wrong option: {c.BRED}{param}{c.WHITE}")
            ok = False

        if run == False and ok == True:
            if log == True:
                print(f"{c.GREEN}\n{param}{c.WHITE} -> {c.YELLOW}{value}{c.WHITE}\n")

        return value
    
    def set_option_rtpbleed(mod, param, value, run, log):
        c = Color()
        ok = True

        if param == "ip":
            if run == False:
                mod.ip = value
            else:
                value = mod.ip
        elif param == "start":
            if run == False:
                mod.start_port = value
            else:
                value = mod.start_port
        elif param == "end":
            if run == False:
                mod.end_port = value
            else:
                value = mod.end_port
        elif param == "loops":
            if run == False:
                mod.loops = value
            else:
                value = mod.loops
        elif param == "payload":
            if run == False:
                mod.payload = value
            else:
                value = mod.payload
        elif param == "delay":
            if run == False:
                mod.delay = value
            else:
                value = mod.delay
        elif param == "output_file":
            if run == False:
                mod.ofile = value
            else:
                value = mod.ofile
        else:
            if log == True:
                print(f"{c.WHITE}Wrong option: {c.BRED}{param}{c.WHITE}")
            ok = False

        if run == False and ok == True:
            if log == True:
                print(f"{c.GREEN}\n{param}{c.WHITE} -> {c.YELLOW}{value}{c.WHITE}\n")

        return value

    def set_option_rtcpbleed(mod, param, value, run, log):
        ok = True

        if param == "ip":
            if run == False:
                mod.ip = value
            else:
                value = mod.ip
        elif param == "output_file":
            if run == False:
                mod.ofile = value
            else:
                value = mod.ofile
        elif param == "start":
            if run == False:
                mod.start_port = value
            else:
                value = mod.start_port
        elif param == "end":
            if run == False:
                mod.end_port = value
            else:
                value = mod.end_port
        elif param == "delay":
            if run == False:
                mod.delay = value
            else:
                value = mod.delay
        else:
            if log == True:
                print(f"{c.WHITE}Wrong option: {c.BRED}{param}{c.WHITE}")
            ok = False

        if run == False and ok == True:
            if log == True:
                print(f"{c.GREEN}\n{param}{c.WHITE} -> {c.YELLOW}{value}{c.WHITE}\n")

        return value

    def set_option_rtpbleedflood(mod, param, value, run, log):
        c = Color()
        ok = True

        if param == "ip":
            if run == False:
                mod.ip = value
            else:
                value = mod.ip
        elif param == "port":
            if run == False:
                mod.port = value
            else:
                value = mod.port
        elif param == "payload":
            if run == False:
                mod.payload = value
            else:
                value = mod.payload
        elif param == "verbose":
            if run == False:
                if value != "0" and value != "1":
                    if log == True:
                        print(f"{c.WHITE}Value {c.BRED}{value} {c.WHITE}is not valid\n")
                    ok = False
                else:
                    mod.verbose = value
            else:
                value = mod.verbose
        else:
            if log == True:
                print(f"{c.WHITE}Wrong option: {c.BRED}{param}{c.WHITE}")
            ok = False

        if run == False and ok == True:
            if log == True:
                print(f"{c.GREEN}\n{param}{c.WHITE} -> {c.YELLOW}{value}{c.WHITE}\n")

        return value

    def set_option_rtpbleedinject(mod, param, value, run, log):
        c = Color()
        ok = True

        if param == "ip":
            if run == False:
                mod.ip = value
            else:
                value = mod.ip
        elif param == "file":
            if run == False:
                mod.file = value
            else:
                value = mod.file
        elif param == "port":
            if run == False:
                mod.port = value
            else:
                value = mod.port
        elif param == "payload":
            if run == False:
                mod.payload = value
            else:
                value = mod.payload
        elif param == "loop":
            if run == False:
                mod.loop = (value == "是")
            else:
                value = "是" if mod.loop else "否"  
        elif param == "force":
            if run == False:
                mod.force = (value == "是")
            else:
                value = "是" if mod.force else "否"
        else:
            if log == True:
                print(f"{c.WHITE}Wrong option: {c.BRED}{param}{c.WHITE}")
            ok = False

        if run == False and ok == True:
            if log == True:
                print(f"{c.GREEN}\n{param}{c.WHITE} -> {c.YELLOW}{value}{c.WHITE}\n")

        return value
    
    def set_option_leak(mod, param, value, run, log):
        c = Color()
        supported_protos = ["UDP", "TCP", "TLS"]

        ok = True

        if param == "ip":
            if run == False:
                mod.ip = value
            else:
                value = mod.ip
        elif param == "file":
            if run == False:
                mod.file = value
            else:
                value = mod.file
        elif param == "rport":
            if run == False:
                mod.rport = value
            else:
                value = mod.rport
        elif param == "proto":
            if run == False:
                value = value.upper()
                if value not in supported_protos:
                    if value == "ALL":
                        mod.proto = "UDP|TCP|TLS"
                    else:
                        if log == True:
                            print(
                                f"{c.WHITE}Protocol {c.BRED}{value} {c.WHITE}is not supported\n"
                            )
                        ok = False
                else:
                    mod.proto = value
            else:
                value = mod.proto
        elif param == "proxy":
            if run == False:
                mod.proxy = value
            else:
                value = mod.proxy
        elif param == "domain":
            if run == False:
                mod.domain = value
            else:
                value = mod.domain
        elif param == "contact_domain":
            if run == False:
                mod.contact_domain = value
            else:
                value = mod.contact_domain
        elif param == "from_name":
            if run == False:
                mod.from_name = value
            else:
                value = mod.from_name
        elif param == "from_user":
            if run == False:
                mod.from_user = value
            else:
                value = mod.from_user
        elif param == "from_domain":
            if run == False:
                mod.from_domain = value
            else:
                value = mod.from_domain
        elif param == "to_name":
            if run == False:
                mod.to_name = value
            else:
                value = mod.to_name
        elif param == "to_user":
            if run == False:
                mod.to_user = value
            else:
                value = mod.to_user
        elif param == "to_domain":
            if run == False:
                mod.to_domain = value
            else:
                value = mod.to_domain
        elif param == "ua":
            if run == False:
                mod.user_agent = value
            else:
                value = mod.user_agent
        elif param == "ppi":
            if run == False:
                mod.ppi = value
            else:
                value = mod.ppi
        elif param == "pai":
            if run == False:
                mod.pai = value
            else:
                value = mod.pai
        elif param == "sdp":
            if run == False:
                mod.sdp = value
            else:   
                value = mod.sdp
        elif param == "sdes":
            if run == False:
                mod.sdes = value
            else:
                value = mod.sdes
        elif param == "user":
            if run == False:
                mod.user = value
            else:
                value = mod.user
        elif param == "pass":
            if run == False:
                mod.pwd = value
            else:
                value = mod.pwd
        elif param == "auth":
            if run == False:
                mod.auth_mode = value
            else:
                value = mod.auth_mode
        elif param == "verbose":
            if run == False:
                if value != "0" and value != "1":
                    if log == True:
                        print(f"{c.WHITE}Value {c.BRED}{value} {c.WHITE}is not valid\n")
                    ok = False
                else:
                    mod.verbose = int(value)
            else:
                value = mod.verbose
        elif param == "output_file":
            if run == False:
                mod.ofile = value
            else:
                value = mod.ofile
        elif param == "log_file":
            if run == False:
                mod.lfile = value
            else:
                value = mod.lfile
        elif param == "ping":
            if run == False:
                mod.ping = value
            else:
                value = mod.ping
        elif param == "local_ip":
            if run == False:
                mod.localip = value
            else:
                value = mod.localip
        else:
            if log == True:
                print(f"{c.WHITE}Wrong option: {c.BRED}{param}{c.WHITE}")
            ok = False

        if run == False and ok == True:
            if log == True:
                print(f"{c.GREEN}\n{param}{c.WHITE} -> {c.YELLOW}{value}{c.WHITE}\n")

        return value
    
    def set_option_send(mod, param, value, run, log):
        c = Color()
        supported_protos = ["UDP", "TCP", "TLS"]
        supported_methods = [
            "REGISTER",
            "SUBSCRIBE",
            "NOTIFY",
            "PUBLISH",
            "MESSAGE",
            "INVITE",
            "OPTIONS",
            "ACK",
            "CANCEL",
            "BYE",
            "PRACK",
            "INFO",
            "REFER",
            "UPDATE",
            ]

        ok = True

        if param == "ip":
            if run == False:
                mod.ip = value
            else:
                value = mod.ip
        elif param == "template":
            if run == False:
                mod.template = value
            else:
                value = mod.template
        elif param == "rport":
            if run == False:
                mod.rport = value
            else:
                value = mod.rport
        elif param == "lport":
            if run == False:
                mod.lport = value
            else:
                value = mod.lport
        elif param == "proto":
            if run == False:
                value = value.upper()
                if value not in supported_protos:
                    if value == "ALL":
                        mod.proto = "UDP|TCP|TLS"
                    else:
                        if log == True:
                            print(
                                f"{c.WHITE}Protocol {c.BRED}{value} {c.WHITE}is not supported\n"
                            )
                        ok = False
                else:
                    mod.proto = value
            else:
                value = mod.proto
        elif param == "proxy":
            if run == False:
                mod.proxy = value
            else:
                value = mod.proxy
        elif param == "method":
            if run == False:
                value = value.upper()
                if value not in supported_methods:
                    if log == True:
                        print(
                            f"{c.WHITE}Method {c.BRED}{value} {c.WHITE}is not supported\n"
                        )
                    ok = False
                else:
                    mod.method = value
            else:
                value = mod.method
        elif param == "domain":
            if run == False:
                mod.domain = value
            else:
                value = mod.domain
        elif param == "contact_domain":
            if run == False:
                mod.contact_domain = value
            else:
                value = mod.contact_domain
        elif param == "from_name":
            if run == False:
                mod.from_name = value
            else:
                value = mod.from_name
        elif param == "from_user":
            if run == False:
                mod.from_user = value
            else:
                value = mod.from_user
        elif param == "from_domain":
            if run == False:
                mod.from_domain = value
            else:
                value = mod.from_domain
        elif param == "from_tag":
            if run == False:
                mod.from_tag = value
            else:
                value = mod.from_tag
        elif param == "to_name":
            if run == False:
                mod.to_name = value
            else:
                value = mod.to_name
        elif param == "to_user":
            if run == False:
                mod.to_user = value
            else:
                value = mod.to_user
        elif param == "to_domain": 
            if run == False:
                mod.to_domain = value
            else:
                value = mod.to_domain
        elif param == "to_tag":
            if run == False:
                mod.to_tag = value
            else:  
                value = mod.to_tag
        elif param == "ua":
            if run == False:
                mod.user_agent = value
            else:
                value = mod.user_agent
        elif param == "ppi":
            if run == False:
                mod.ppi = value
            else:
                value = mod.ppi
        elif param == "pai":
            if run == False:
                mod.pai = value
            else:
                value = mod.pai
        elif param == "header":
            if run == False:
                mod.header = value
            else:
                value = mod.header
        elif param == "branch":
            if run == False:
                mod.branch = value
            else:
                value = mod.branch
        elif param == "callid":
            if run == False:
                mod.callid = value
            else:
                value = mod.callid
        elif param == "cseq":
            if run == False:
                mod.cseq = value
            else:
                value = mod.cseq
        elif param == "digest":
            if run == False:
                mod.digest = value
            else:
                value = mod.digest
        elif param == "sdp":
            if run == False:
                mod.sdp = value
            else:
                value = mod.sdp
        elif param == "sdes":
            if run == False:
                mod.sdes = value
            else:
                value = mod.sdes
        elif param == "user":
            if run == False:
                mod.user = value
            else:
                value = mod.user
        elif param == "pass":
            if run == False:
                mod.pwd = value
            else:
                value = mod.pwd
        elif param == "verbose":
            if run == False:
                if value != "0" and value != "1":
                    if log == True:
                        print(f"{c.WHITE}Value {c.BRED}{value} {c.WHITE}is not valid\n")
                    ok = False
                else:
                    mod.verbose = value
            else:
                value = mod.verbose
        elif param == "output_file":
            if run == False:
                mod.ofile = value
            else:
                value = mod.ofile
        elif param == "timeout":
            if run == False:
                mod.timeout = int(value)
            else:
                value = mod.timeout
        elif param == "local_ip":
            if run == False:
                mod.localip = value
            else:
                value = mod.localip
        else:
            if log == True:
                print(f"{c.WHITE}Wrong option: {c.BRED}{param}{c.WHITE}")
            ok = False

        if run == False and ok == True:
            if log == True:
                print(f"{c.GREEN}\n{param}{c.WHITE} -> {c.YELLOW}{value}{c.WHITE}\n")

        return value