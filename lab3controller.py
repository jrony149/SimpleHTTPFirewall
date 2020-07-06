# Lab 3 Skeleton
#
# Based on of_tutorial by James McCauley

from pox.core import core
import pox.lib.packet as pkt
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Firewall (object):
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
    
  

  def do_firewall (self, packet, packet_in):
    # The code in here will be executed for every packet.
    
   msg = of.ofp_packet_out(data=packet)
   host1MAC = "00:00:00:00:00:01" #hardcoding mac addresses
   host4MAC = "00:00:00:00:00:04"

   my_match = of.ofp_flow_mod() #creating instance of ofp_flow_mod()
   my_match.match = of.ofp_match.from_packet(packet)#setting match structure equal to packet data
   
   ip = packet.find('ipv4')#using find() function on respective relevant protocols for use in conditional statements
   tcp = packet.find('tcp')

   arp = packet.find('arp')
   icmp = packet.find('icmp')

   if (tcp != None and ip != None):

    # print "From tcp/ip"

     msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))

     self.connection.send(msg)

     my_match.hard_timeout = 300

     my_match.priority = 5

     my_match.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))#defines the action for rule

     self.connection.send(my_match)#alters the flow table and appends the rule

   if (arp) != None:

    # print "From arp"

     msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))

     self.connection.send(msg)#flooding the packet if it's the first instance of that packet being sent to the controller.

     my_match.hard_timeout = 300

     #print "The dl_type is: ",  my_match.match.dl_type
     
     my_match.priority = 4

     my_match.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))#defines action for rule

     self.connection.send(my_match)#alters the flow table in switch and appends the rule

     

   if (icmp != None):

   # print "From icmp"

    if ((str(packet.src) == host1MAC and str(packet.dst) == host4MAC)):  #matching on MAC addresses to discern source and destination
      
     # print "From h1/h4"      

      msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))

      self.connection.send(msg)

      my_match.hard_timeout = 300 #setting hard timeout for rule

      my_match.priority = 3

      my_match.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))#defines action for rule

      self.connection.send(my_match)#alters the flow table in switch and appends the rule

    elif ((str(packet.src) == host4MAC and str(packet.dst) == host1MAC)):

     # print "from h4/h1"

      msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))

      self.connection.send(msg)

      my_match.hard_timeout = 300 #setting hard timeout for rule

      my_match.priority = 2

      my_match.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))#defines action for rule

      self.connection.send(my_match)#alters the flow table in switch and appends the rule
   
    else:

     # print "from icmp drop"

      msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))

      self.connection.send(msg)

      my_match.hard_timeout = 300 #setting hard timeout for rule

      my_match.actions.append(of.ofp_action_output(port=of.OFPP_NONE))#defines action for rule

      self.connection.send(my_match)
  
      


      

   elif ip != None and tcp == None and arp == None and icmp == None:

      print "from general drop"

      msg.actions.append(of.ofp_action_output(port=of.OFPP_NONE))

      self.connection.send(msg)
      
      my_match.hard_timeout = 300

      my_match.priority = 1

      my_match.actions.append(of.ofp_action_output(port=of.OFPP_NONE))
      
      self.connections.send(my_match)
  
   

      
  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_firewall(packet, packet_in)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
