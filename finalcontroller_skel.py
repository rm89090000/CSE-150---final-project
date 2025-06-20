# Final Skeleton
#
# Hints/Reminders from Lab 3:
#
# To check the source and destination of an IP packet, you can use
# the header information... For example:
#
# ip_header = packet.find('ipv4')
#
# if ip_header.srcip == "1.1.1.1":
# print "Packet is from 1.1.1.1"
#
# Important Note: the "is" comparison DOES NOT work for IP address
# comparisons in this way. You must use ==.
#
# To send an OpenFlow Message telling a switch to send packets out a
# port, do the following, replacing <PORT> with the port number the
# switch should send the packets out:
#
# msg = of.ofp_flow_mod()
# msg.match = of.ofp_match.from_packet(packet)
# msg.idle_timeout = 30
# msg.hard_timeout = 30
#
# msg.actions.append(of.ofp_action_output(port = <PORT>))
# msg.data = packet_in
# self.connection.send(msg)
#
# To drop packets, simply omit the action.
#
from pox.core import core
import pox.openflow.libopenflow_01 as of
log = core.getLogger()
class Final (object):
"""
A Firewall object is created for each switch that connects.
A Connection object for that switch is passed to the __init__ function.
"""
def __init__ (self, connection):
# Keep track of the connection to the switch so that we can
# send it messages!
self.connection = connection
# This binds our PacketIn event listener
connection.addListeners(self)
def do_final (self, packet, packet_in, port_on_switch, switch_id):
ips = packet.find('ipv4')
icmps = packet.find('icmp')
if ips is None:
msg = of.ofp_packet_out()
msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
msg.data = packet_in
self.connection.send(msg)
return
source = str(ips.srcip)
dest = str(ips.dstip)
floor1_hosts =["128.114.1.101", "128.114.1.102", "128.114.1.103",
"128.114.1.104"]
floor2_hosts =["128.114.2.201", "128.114.2.202", "128.114.2.203",
"128.114.2.204"]
#untrusted host
if source == "108.35.24.113":
if dest in floor1_hosts or dest in floor2_hosts or dest == "128.114.3.178":
if icmps is not None:
print("Block ICMP")
return
if dest == "128.114.3.178":
print("Block IP")
return
#trusted host
if source == "192.47.38.109":
if dest in floor2_hosts:
if icmps is not None:
print("Block ICMP")
return
if dest == "128.114.3.178":
print("Block ip addresses")
return
if source in floor2_hosts and dest in floor1_hosts:
if icmps is not None:
print("Block ICMP")
return
if source in floor1_hosts and dest=="128.114.3.178":
print("Allow")
output = None
if switch_id == 1:
if dest == "128.114.1.101":
output = 1
elif dest == "128.114.1.102":
output = 2
else:
output = 3
elif switch_id == 2:
if dest == "128.114.1.103":
output = 1
elif dest =="128.114.1.104":
output = 2
else:
output = 3
elif switch_id == 3:
if dest == "128.114.2.201":
output = 1
elif dest == "128.114.2.202":
output = 2
else:
output = 3
elif switch_id == 4:
if dest == "128.114.2.203":
output = 1
elif dest == "128.114.2.204":
output = 2
else:
output = 3
elif switch_id == 5:
if dest == "128.114.3.178":
output = 7
elif dest == "192.47.38.109":
output = 1
elif dest == "108.35.24.113":
output = 2
elif "128.114.1." in dest:
if dest == "128.114.1.101" or dest == "128.114.1.102":
output = 3
else:
output = 4
elif "128.114.2." in dest:
if dest == "128.114.2.201" or dest == "128.114.2.202":
output = 5
else:
output = 6
elif switch_id == 6:
if dest == "128.114.3.178":
output = 2
elif dest in floor1_hosts or dest in floor2_hosts or dest == "192.47.38.109"
or dest == "108.35.24.113":
output = 1
if output is not None:
msg = of.ofp_flow_mod()
msg.match = of.ofp_match.from_packet(packet)
msg.idle_timeout = 30
msg.hard_timeout = 30
msg.actions.append(of.ofp_action_output(port=output))
msg.data = packet_in
self.connection.send(msg)
else:
print("Drop and flood")
msg = of.ofp_flow_mod()
msg.match = of.ofp_match.from_packet(packet)
msg.idle_timeout = 30
msg.hard_timeout = 30
self.connection.send(msg)
return
def _handle_PacketIn (self, event):
"""
Handles packet in messages from the switch.
"""
packet = event.parsed # This is the parsed packet data.
if not packet.parsed:
log.warning("Ignoring incomplete packet")
return
packet_in = event.ofp # The actual ofp_packet_in message.
self.do_final(packet, packet_in, event.port, event.dpid)
def launch ():
"""
Starts the component
"""
def start_switch (event):
log.debug("Controlling %s" % (event.connection,))
Final(event.connection)
core.openflow.addListenerByName("ConnectionUp", start_switch)
