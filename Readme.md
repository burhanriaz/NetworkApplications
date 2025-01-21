# NetworkApplications.py
Network Applications

A collection of Network Applications
positional arguments:
  {ping,p,traceroute,t,mtroute,mt,web,w, proxy,x}
                      sub-command help 
ping (p)                      run ping
traceroute (t)          run traceroute
mtroute (mt)            run traceroute
web (w)                 run web server
proxy (x)               run proxy
options:
-h, --help
show help message and exit

e.g. python3 NetworkApplicationsFinal.py ping google.com, python3 NetworkApplicationsFinal.py traceroute -p icmp google.com
NOTE: Only works on computers with SUDO privileges
NOTE 2: Traceroute and Multi-threaded Traceroute only works on Linux platforms
NOTE 3: Webserver and proxy only works on websites without https encryption
