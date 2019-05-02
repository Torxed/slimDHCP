import sys, struct
from socket import *
from select import epoll, EPOLLIN

args = {}
positionals = []
for arg in sys.argv[1:]:
	if '--' == arg[:2]:
		if '=' in arg:
			key, val = [x.strip() for x in arg[2:].split('=')]
		else:
			key, val = arg[2:], True
		args[key] = val
	else:
		positionals.append(arg)

if not 'interface' in args: args['interface'] = 'eth0'
if not 'subnet' in args: args['subnet'] = '192.168.0.0'
if not 'netmask' in args: args['netmask'] = '255.255.0.0'
if not 'gateway' in args: args['gateway'] = args['subnet'][:args['subnet'].rfind('.')] + '.1' # TODO: Don't assume
if not 'pxe' in args: args['pxe'] = '/ipxe.efi'
if not 'pxe_dir' in args: args['pxe_dir'] = './pxe_files'

def byte_to_bin(bs, bin_map=None):
	"""
	Has two functions:

	1) Converts a bytes() type string into a binary representation in str() format

	2) Boundles each binary representation in groups/blocks given by the bin_map list()
	   [1, 1, 2] would group into [['00000000'], ['01010101'], ['10011010', '00110101']]
	   - Any raiming data till be added in a list [...] at the end to not loose data.

	TODO: handle bin_map = None
	"""
	raw = []
	index = 0
	for length in bin_map:
		mipmap = []
		for i in bs[index:index+length]:
			mipmap.append('{0:b}'.format(i).zfill(8))
		raw.append(mipmap)
		index += length
	if index < len(bs):
		mipmap = []
		for i in bs[index:]:
			mipmap.append('{0:b}'.format(i).zfill(8))
		raw.append(mipmap)
	return raw

def binToObj(b, func):
	""" takes a bytes() string and calls func() on each int() value of the bytes() string """
	return [func(i) for i in b]

def bigInt(num):
	""" Converts a larger >255 number into a bytes() string by padding """
	ret_list = []
	while num > 255:
		num -= 1
		if len(ret_list) == 0:
			ret_list.append(1)
		elif ret_list[-1] + 1 > 255:
			ret_list.append(0)
		ret_list[-1] += 1
	ret_list.append(num)
	return b''.join([hexInt(i) for i in ret_list[::-1]])

def bin_str_to_byte(s):
	""" Converts a binary str() representation into a bytes() string """
	b = b''
	for index in range(len(s)):
		b += bytes([int(s[index],2)])
	return b

def bytes_to_hex(b):
	s = ''
	for i in b:
		s += '{:02X}'.format(i) # Int -> HEX
	return s

def binInt(num):
	## TODO: Discard, probably not doing what i initially thought it did (results are similar, up to a certain number)
	##   binInt(53), hexInt(53)  vs  binInt(255), hexInt(255) : <
	""" Converts a int() to bytes() object with proper \x00 declaration (and not a hex(num) representation) """
	#return bytes(chr(num), 'UTF-8')

	#new:
	return struct.pack('B', num)

def hexInt(num):
	""" Converts a int() to hex() representation in bytes() format. """
	return bytearray.fromhex(hex(num)[2:].zfill(2))

def int_array_to_hexbytes(ia):
	""" takes a list() of int() types and convert them to a bytes() string with proper hex(\x00) declaration """
	b = b''
	for i in ia:
		b += hexInt(int(i))
	return b

def b_fill(byte, l):
	""" Pads a bytes() string with \x00 """
	return b''.join([b'\x00'*(l-len(byte)), byte])

def ip_to_int(ip):
	return [int(x) for x in ip.split('.')]

def gen_ip(subnet, netmask, exludes=[]):
	subnet = b''.join([struct.pack('B', int(x)) for x in subnet.split(b'.')])
	netmask = b''.join([struct.pack('B', int(x)) for x in netmask.split(b'.')])
	## TODO: Add support for partial subnets
	## ++ bigInt needs a parameter for this!
	octets = netmask.count(b'\x00')+1
	for ip in range(255*(netmask.count(b'\x00')+1)):
		if ip in (0, 1, 255): continue ## Avoid broadcast and looping replace (replacing \x00 with \x00, for now)

		ending_octets = b_fill(bigInt(ip), subnet.count(b'\x00'))
		ip = subnet[:len(subnet)-len(ending_octets)] + ending_octets
		if not ip in exludes:
			return ip

if not 'datastore' in __builtins__:
	__builtins__['datastore'] = {
		'dhcp' : {
			'interface' : args['interface'],
			'subnet' : args['subnet'],
			'netmask' : args['netmask'],
			'gateway' : args['gateway'],
			'pxe' : args['pxe'], # Bootloader that supports HTTP chaining, will default to http://<gateway>:80/default.ipxe
			'pxe_dir' : args['pxe_dir'],
			'*leases' : {},  # MAC -> IP
			'*ip_uses' : {}, # IP -> MAC
			'*address_space' : {}
		}
	}

class dhcp_serve():
	def __init__(self, interface=None):
		if not interface:
			if 'interface' in datastore['dhcp'] and datastore['dhcp']['interface']:
				interface = datastore['dhcp']['interface']
			else:
				interface = sorted([x for x in psutil.net_if_addrs().keys() if not x == 'lo'])[0]
		self.sock = socket(AF_INET, SOCK_DGRAM) # UDP

		## https://www.freepascal.org/docs-html/current/rtl/sockets/index-2.html
		self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		self.sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
		## Not sure we need this:
		self.sock.setsockopt(SOL_SOCKET, 25, bytes(interface, 'UTF-8')+b'\0') ## http://fxr.watson.org/fxr/source/net/wanrouter/af_wanpipe.c?v=linux-2.6
		self.sock.bind(('255.255.255.255', 67)) # And lets listen on port 67 broadcasts (UDP)
		self.main_so_id = self.sock.fileno()

		self.pollobj = epoll()
		self.pollobj.register(self.main_so_id, EPOLLIN)

	def poll(self, timeout=0.001, fileno=None):
		d = dict(self.pollobj.poll(timeout))
		if fileno: return d[fileno] if fileno in d else None
		return d

	def close(self):
		self.pollobj.unregister(self.main_so_id)
		self.sock.close()

	def parse(self):
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

		if self.poll():
			data, addr = self.sock.recvfrom(8192) # Could potentially lower tihs value, not sure if that would gain anything tho.

			## Convert the 
			binary = list(byte_to_bin(data, bin_map=dhcp_packet_struct))

			request = {}
			for index in range(len(binary)):
				request[dhcp_protocol[index]] = {'binary' : binary[index], 'bytes' : bin_str_to_byte(binary[index]), 'hex' : None}
				request[dhcp_protocol[index]]['hex'] = bytes_to_hex(request[dhcp_protocol[index]]['bytes'])


			## Extract the DHCP options
			dhcp_options = request['other']['binary']
			num_of_dhcp_options = ord(bin_str_to_byte([dhcp_options[1]]))
			request['dhcp_options'] = {}

			for item in range(num_of_dhcp_options):
				request['dhcp_options'][item] = { 'binary' : dhcp_options[item],
												  'bytes' : bin_str_to_byte([dhcp_options[item]])}

			## If the MAC (in bytes() format) isn't in the known list
			## generate a new IP for that person. For now we don't have a cleanup period for this.
			## (basic basic for now)
			if not request['client mac']['hex'] in datastore['dhcp']['*leases']:
				ip_leased = gen_ip(bytes(datastore['dhcp']['subnet'], 'UTF-8'), bytes(datastore['dhcp']['netmask'], 'UTF-8'), datastore['dhcp']['*ip_uses'])
				if ip_leased:
					datastore['dhcp']['*leases'][request['client mac']['hex']] = ip_leased
					datastore['dhcp']['*ip_uses'][ip_leased] = request['client mac']['hex']
				else:
					raise ValueError('Out of IP addresses..') # TODO: make a clean "continue" / "check if old leases expired"

			packet = b''
			if request['msg type']['bytes'] == b'\x01': # Message type: Boot request (1)
				packet += b'\x02'   #Message type: DHCP Offer
				packet += b'\x01'   #Hardware type: Ethernet
				packet += b'\x06'   #Hardware address length: 6
				packet += b'\x00'   #Hops: 0
				packet += request['transaction id']['bytes']   #Transaction ID
				packet += b'\x00\x00'  #Seconds elapsed: 0
				packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
				packet += b'\x00\x00\x00\x00'   # Client IP address: 0.0.0.0
				packet += datastore['dhcp']['*leases'][request['client mac']['hex']]   # The IP offered to the client
				if datastore['dhcp']['pxe']:
					## --pxe=192.168.0.1:pxe_boot.bin
					if not ':' in datastore['dhcp']['pxe']:
						# 192.168.0.1 -> b'\xac\x1+\r%'
						packet += int_array_to_hexbytes(datastore['dhcp']['gateway'].split('.'))
					else:
						# 192.168.0.1:/path -> 192.168.0.1 -> b'\xac\x1+\r%'
						packet += int_array_to_hexbytes(datastore['dhcp']['pxe'].split(':',1)[0].split('.'))
				else:
					packet += b'\x00\x00\x00\x00'   # "Next server", if not PXE, 0.0.0.0
				packet += b'\x00\x00\x00\x00'   # Relay agent IP address: 0.0.0.0 because I have no idea what this is heh
				packet += request['client mac']['bytes'] # Client MAC address: 00:26:9e:04:1e:9b
				packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   # Client hardware address padding: (Legacy stuff)
				packet += b'\x00' * 64  # Server host name not supplied, so Zero this out
				## Simple way of adding a pxe-file:
				#if datastore['dhcp']['pxe']:
				#	## --pxe=192.168.0.1:pxe_boot.bin
				#	if ':' in datastore['dhcp']['pxe']:
				#		pxe_file = datastore['dhcp']['pxe'].split(':',1)[1]
				#	else:
				#		pxe_file = datastore['dhcp']['pxe']
				#	packet += bytes(pxe_file, 'UTF-8')+(b'\x00' * (128-len(pxe_file))) # Pxe filename
				#else:
				packet += b'\x00' * 128 # Otherwise we zero it out
				packet += b'\x63\x82\x53\x63' #b'\x63\x82\x53\x63'   #Magic cookie: DHCP

				## This is basically what differs in a basic basic DHCP sequence, the message type recieved and matching response.
				if request['option 53']['bytes'][-1] == 1: # DHCP Discover
					print('[DISCOVER] {} (Offering: {})'.format(':'.join([item[2:].zfill(2) for item in binToObj(request['client mac']['bytes'], hex)]), '.'.join([str(item) for item in binToObj(datastore['dhcp']['*leases'][request['client mac']['hex']], int)])))
					#print('[DISCOVER]', )
					packet += binInt(53)+b'\x01\x02'   # DHCP Offer
				if request['option 53']['bytes'][-1] == 3: # DHCP Request
					print('[PROVIDED] {} with {}'.format(':'.join([item[2:].zfill(2) for item in binToObj(request['client mac']['bytes'], hex)]), '.'.join([str(item) for item in binToObj(datastore['dhcp']['*leases'][request['client mac']['hex']], int)])))
					#print('[PROVIDED]', '.'.join([str(item) for item in binToObj(datastore['dhcp']['*leases'][request['client mac']['hex']], int)]))
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
				packet += binInt(54)+b'\x04'+int_array_to_hexbytes(ip_to_int(datastore['dhcp']['gateway'])) #DHCP Server Identifier
				packet += binInt(51)+b'\x04\x00\x00\xa8\xc0'#+b_fill(binInt(43200), 4) #Lease time (seconds)
				## Begin PXE stuff:
				if datastore['dhcp']['pxe']:
					renewal_time = struct.pack('>I', 21600)
					rebind_time = struct.pack('>I', 37800)
					broadcast = int_array_to_hexbytes(ip_to_int('172.16.255.255'))
					packet += binInt(67)+struct.pack('B', len(datastore['dhcp']['pxe'])+1)+bytes(datastore['dhcp']['pxe'], 'UTF-8')+b'\0' # Bootfile name
					packet += binInt(58)+struct.pack('B', len(renewal_time))+renewal_time # Renewal Time Value
					packet += binInt(59)+struct.pack('B', len(rebind_time))+rebind_time # Rebinding Time Value
					packet += binInt(1)+b'\x04'+int_array_to_hexbytes(ip_to_int(datastore['dhcp']['netmask'])) #Subnet mask
					packet += binInt(28)+struct.pack('B', len(broadcast))+broadcast # Broadcast Address
					packet += binInt(3)+b'\x04'+int_array_to_hexbytes(ip_to_int(datastore['dhcp']['gateway'])) # Router
					packet += binInt(66)+struct.pack('B', len(datastore['dhcp']['gateway'])+1)+bytes(datastore['dhcp']['gateway'], 'UTF-8')+b'\0' # TFTP Server Name (IP valid)
					packet += binInt(210)+struct.pack('B', len('/arch/'))+bytes('/arch/', 'UTF-8') # PXE Path Prefix
					packet += binInt(209)+struct.pack('B', len('loader/loader.conf'))+bytes('loader/loader.conf', 'UTF-8') # PXE Configuration file
					packet += binInt(6)+b'\x08'+int_array_to_hexbytes([8,8,8,8])+int_array_to_hexbytes([4,4,4,4]) # Domain name servers

				packet += b'\xff'   #End Option
				#packet += b'\x00'*22 # Padding, not sure how much is needed atm but this does it :)

			if len(packet) > 0:
				self.sock.sendto(packet, ('255.255.255.255', 68))

if __name__ == '__main__':
	pxe = dhcp_serve()
	while 1:
		if pxe.poll():
			pxe.parse()