from socket import *
from binary.helpers import *

def gen_ip(subnet, netmask, exludes=[]):
	## TODO: Add support for partial subnets
	## ++ bigInt needs a parameter for this!
	octets = netmask.count(b'\x00')+1
	for ip in range(255*(netmask.count(b'\x00')+1)):
		if ip == 0 or ip == 255: continue ## Avoid broadcast and looping replace (replacing \x00 with \x00, for now)

		generated_ip = b_fill(bigInt(ip), subnet.count(b'\x00'))
		ip = subnet.replace(b'\x00'*len(generated_ip), generated_ip)
		if not ip in exludes:
			return ip

__boot__ = b'/pxe_syslinux/lpxelinux.0'
#__boot__ = b'/pxe_grub/grub.pxe'  # <-- Almost works
#__boot__ = b'/pxe_grub/grub2pxe'
#__boot__ = b'/pxe_grub/bootx64.efi'
__subnet__ = int_array_to_hex([172,16,0,0])
__netmask__ = int_array_to_hex([255,255,255,0])

## Set up a memory of which IP's we've given out this session
## And start by adding our own IP to that pool hehe.
__actives__ = {}
__clients__ = {'localhost' : gen_ip(__subnet__, __netmask__, __actives__)}
__actives__[__clients__['localhost']] = 'localhost'

## a TFTP server (extremely basic) is included
#  - Uncomment the line below or start a tftp server along side this script
#    in order to host the __boot__ file.
#
# import tftp 

sock = socket(AF_INET, SOCK_DGRAM) # UDP
sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
sock.setsockopt(SOL_SOCKET, 25, b'ens37\0') # Interface which to bind the broadcast domain to
sock.bind(('255.255.255.255', 67)) # And lets listen on port 67 broadcasts (UDP)

dhcp_packet_struct = [1, 1, 1, 1, 4, 2, 2, 4, 4, 4, 4, 6, 10, 64, 128, 4, 3]
dhcp_protocol = ['msg type', 'hw type', 'hw addr len', 'hops',
				 'transaction id',
				 'elapsed', 'bootp flags',
				 'client ip',
				 'client assigned ip',
				 'server ip',
				 'relay agent',
				 'client mac',
				 'client padding',
				 'server hostname',
				 'boot file',
				 'magic cookie',
				 'option 53', # This is dangerous to assume
				 'other']

while True:
	data, addr = sock.recvfrom(8192) # Could potentially lower tihs value, not sure if that would gain anything tho.

	## Convert the 
	binary = list(byte_to_bin(data, bin_map=dhcp_packet_struct))

	request = {}
	for index in range(len(binary)):
		request[dhcp_protocol[index]] = {'binary' : binary[index], 'hex' : bin_str_to_byte(binary[index])}


	## Extract the DHCP options
	dhcp_options = request['other']['binary']
	num_of_dhcp_options = ord(bin_str_to_byte([dhcp_options[1]]))
	request['dhcp_options'] = {}

	for item in range(num_of_dhcp_options):
		request['dhcp_options'][item] = { 'binary' : dhcp_options[item],
										  'hex' : bin_str_to_byte([dhcp_options[item]])}

	## If the MAC (in bytes() format) isn't in the known list
	## generate a new IP for that person. For now we don't have a cleanup period for this.
	## (basic basic for now)
	if not request['client mac']['hex'] in __clients__:
		__clients__[request['client mac']['hex']] = gen_ip(__subnet__, __netmask__, __actives__)
		__actives__[__clients__[request['client mac']['hex']]] = request['client mac']['hex']

	pxe_host = int_array_to_hex([172,16,0,1]) ## Could use __clients__['localhost'] but not as intuative
	pxe_file = __boot__#b'/pxelinux.0'
	packet = b''
	if request['msg type']['hex'] == b'\x01': # Message type: Boot request (1)
		packet += b'\x02'   #Message type: DHCP Offer
		packet += b'\x01'   #Hardware type: Ethernet
		packet += b'\x06'   #Hardware address length: 6
		packet += b'\x00'   #Hops: 0
		packet += request['transaction id']['hex']   #Transaction ID
		packet += b'\x00\x00'  #Seconds elapsed: 0
		packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
		packet += b'\x00\x00\x00\x00'   # Client IP address: 0.0.0.0
		packet += __clients__[request['client mac']['hex']]   # The IP offered to the client
		if pxe_file:
			packet += pxe_host
		else:
			packet += b'\x00\x00\x00\x00'   # "Next server", if not PXE, 0.0.0.0
		packet += b'\x00\x00\x00\x00'   # Relay agent IP address: 0.0.0.0 because I have no idea what this is heh
		packet += request['client mac']['hex'] # Client MAC address: 00:26:9e:04:1e:9b
		packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   # Client hardware address padding: (Legacy stuff)
		packet += b'\x00' * 64  # Server host name not supplied, so Zero this out
		if pxe_file:
			packet += pxe_file+(b'\x00' * (128-len(pxe_file))) # Pxe filename
		else:
			packet += b'\x00' * 128 # Otherwise we zero it out
		packet += b'\x63\x82\x53\x63' #b'\x63\x82\x53\x63'   #Magic cookie: DHCP

		## This is basically what differs in a basic basic DHCP sequence, the message type recieved and matching response.
		if request['option 53']['hex'][-1] == 1: # DHCP Discover
			print('[DISCOVER]', ':'.join([item[2:].zfill(2) for item in binToObj(request['client mac']['hex'], hex)]))
			packet += binInt(53)+b'\x01\x02'   # DHCP Offer
		if request['option 53']['hex'][-1] == 3: # DHCP Request
			print('[PROVIDED]', '.'.join([str(item) for item in binToObj(__clients__[request['client mac']['hex']], int)]))
			packet += binInt(53)+b'\x01\x05'   # Message Type ACK 
		""" <<<
			1 = DHCP Discover message (DHCPDiscover).
			2 = DHCP Offer message (DHCPOffer).
			3 = DHCP Request message (DHCPRequest).
			4 = DHCP Decline message (DHCPDecline).
			5 = DHCP Acknowledgment message (DHCPAck).
			6 = DHCP Negative Acknowledgment message (DHCPNak).
			7 = DHCP Release message (DHCPRelease).
			8 = DHCP Informational message (DHCPInform).
		"""
		packet += binInt(54)+b'\x04'+int_array_to_hex([172,16,0,1]) #DHCP Server Identifier
		packet += binInt(51)+b'\x04\x00\x00\xa8\xc0'#+b_fill(binInt(43200), 4) #Lease time (seconds)
		packet += binInt(1)+b'\x04'+__netmask__ #Subnet mask
		packet += binInt(3)+b'\x04'+int_array_to_hex([172,16,0,1]) # Router
		packet += binInt(6)+b'\x08'+int_array_to_hex([8,8,8,8])+int_array_to_hex([4,4,4,4]) # Domain name servers

		packet += b'\xff'   #End Option
		packet += b'\x00'*22 # Padding, not sure how much is needed atm but this does it :)

	if len(packet) > 0:
		sock.sendto(packet, ('255.255.255.255', 68))
