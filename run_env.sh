gnome-terminal -e 'sudo mn --topo dptopo --custom /home/jozef/PycharmProjects/DP_Security_improvements/topo1.py --controller=remote --switch ovsk,protocols=OpenFlow15'
ryu-manager /home/jozef/PycharmProjects/DP_Security_improvements/simple_switch_15.py
#ryu-manager /home/jozef/PycharmProjects/DP_Security_improvements/simple_switch_stp_15.py

sudo mn --topo dptopo --custom /home/jozef/PycharmProjects/DP_Security_improvements/topo1.py --controller=remote --switch ovsk,protocols=OpenFlow14

ryu-manager /home/jozef/PycharmProjects/DP_Security_improvements/simple_switch_14.py

IPERF UDP SERVER:
iperf -s -u -p 5566 -i 1
iperf -s -i 1 -u

IPERF UDP CLIENT:
iperf -c 10.0.0.1 -u -t 5 -p 5566
iperf -c 10.0.0.1 -u -b 9pps -t 1

SimpleHTTPServer
python -m SimpleHTTPServer 80

HTTP client
wget -O - 10.0.0.1

