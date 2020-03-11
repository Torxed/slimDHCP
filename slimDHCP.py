import sys, struct, json, abc, ipaddress #Python v3.3
from socket import *
from select import epoll, EPOLLIN

## Basic version of arg.parse() supporting:
## * --key=value
## * slimDHCP.py positional1 positional2
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

if not 'interface' in args:
	print('\n  [!] Mandatory: --interface=<ifname>') #args['interface'] = 'ens4u1u4'
	print()
	print('Usage: ')
	print(' --interface=eth0          (mandatory)')
	print(' --subnet=192.168.1.0/24   (default)')
	print(' --gateway=192.168.1.1     (default)')
	print(' --pxe_bin=ipxe.efi')
	print(' --pxe_dir=/srv/pxe/')
	print(' --filter_clients=\'{"de:ad:be:ef:00:01" : true, "de:ad:be:ef:00:02" : "192.168.1.10"}\'')
	exit(1)
if not 'subnet' in args: args['subnet'] = '192.168.1.0'
if not 'netmask' in args: args['netmask'] = '255.255.255.0' # Optional, if it's given on the subnet definition.
if not 'gateway' in args: args['gateway'] = None # Takes the first host of the subnet by default
if not 'pxe_bin' in args: args['pxe_bin'] = None # Point toward a efi file, for instance: '/ipxe.efi'
if not 'pxe_dir' in args: args['pxe_dir'] = './'# './pxe_files'
if not 'pxe_config' in args: args['pxe_config'] = 'loader/loader.conf'
if not 'pxe_server' in args:
	if args['pxe_bin']:
		args['pxe_server'] = args['gateway']
	else:
		args['pxe_server'] = '0.0.0.0'
if not 'filter_clients' in args: args['filter_clients'] = '{}' # JSON structure of clients

## Append the netmask/cidr on to the subnet definition if not already given.
if not '/' in args['subnet']: args['subnet'] = f"{args['subnet']}/{args['netmask']}"

## Convert arguments to workable elements:
args['subnet'] = ipaddress.ip_network(args['subnet'])
args['pxe_server'] = ipaddress.ip_address(args['pxe_server'])
args['filter_clients'] = json.loads(args['filter_clients'])
# Designate a gateway if none was given, take the first host of our subnet element:
if not args['gateway']:
	for host in args['subnet'].hosts():
		args['gateway'] = host
		break

## Set up the global dictionary/config:
if not 'datastore' in __builtins__.__dict__:
	__builtins__.__dict__['datastore'] = {
		'dhcp' : {
			'interface' : args['interface'],
			'subnet' : args['subnet'],
			'netmask' : args['netmask'],
			'gateway' : args['gateway'],
			#'pxe' : args['pxe'], # Bootloader that supports HTTP chaining, will default to http://<gateway>:80/default.ipxe
			'pxe_server' : args['pxe_server'],
			'pxe_bin' : args['pxe_bin'],
			'pxe_dir' : args['pxe_dir'],
			'*leases' : {
				'<internal self reference>' : args['gateway']
			},  # MAC -> IP
			'*ip_uses' : {
				args['gateway'] : '<interface self reference>'
			}, # IP -> MAC
			'*address_space' : {}
		}
	}

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
	return [int(x) for x in str(ip).split('.')]

def gen_ip(subnet, exludes=[]):
	#subnet = b''.join([struct.pack('B', int(x)) for x in subnet.split(b'.')])
	#netmask = b''.join([struct.pack('B', int(x)) for x in netmask.split(b'.')])
	## TODO: Add support for partial subnets
	## ++ bigInt needs a parameter for this!
	#octets = netmask.count(b'\x00')+1
	#for ip in range(255*(netmask.count(b'\x00')+1)):
	#	if ip in (0, 1, 255): continue ## Avoid broadcast and looping replace (replacing \x00 with \x00, for now)

	#	ending_octets = b_fill(bigInt(ip), subnet.count(b'\x00'))
	#	ip = subnet[:len(subnet)-len(ending_octets)] + ending_octets
	#	if not ip in exludes:
	#		return ip
	for host in subnet.hosts():
		if not host in exludes:
			return host

def human_mac(obj):
	if type(obj) == bytes:
		return ':'.join([item[2:].zfill(2) for item in binToObj(obj, hex)])
	else:
		raise KeyError('Not yet implemented: human_mac(hex)')

def human_readable(l, separator):
	return f"{separator}".join([str(x) for x in l])

def ip_to_bytes(ip_obj):
	return struct.pack('>I', int(ip_obj))

def get_lease(mac):
	if mac in datastore['dhcp']['*leases']:
		return datastore['dhcp']['*leases'][mac]
	else:
		return None

dhcp_message_types = {
	'OFFER' : 2,
	'ACK' : 5
}
class dhcp_option(abc.ABCMeta):
	@abc.abstractmethod
	def TYPE(_type):
		if not _type in dhcp_message_types: raise KeyError('DHCP Message type not defined in dhcp_message_types.')

		"""
		@option: 54
		@link: https://tools.ietf.org/html/rfc2132#section-9.6
		"""
		
		""" 
		<<<
			1 = DHCP Discover message (DHCPDiscover).
			2 = DHCP Offer message (DHCPOffer).
			3 = DHCP Request message (DHCPRequest).
			4 = DHCP Decline message (DHCPDecline).
			5 = DHCP Acknowledgment message (DHCPAck).
			6 = DHCP Negative Acknowledgment message (DHCPNak).
			7 = DHCP Release message (DHCPRelease).
			8 = DHCP Informational message (DHCPInform).
		>>>
		"""
		# option | length | type
		return binInt(53)+b'\x01'+struct.pack('B', dhcp_message_types[_type])   # Message Type ACK

	@abc.abstractmethod
	def dhcp_offer():
		return b'\x02'

	@abc.abstractmethod
	def hardware_type(_type):
		return b'\x01' # ethernet (only support :)

	@abc.abstractmethod
	def address_length(len):
		return b'\x06'

	@abc.abstractmethod
	def trasnaction_id(request):
		return request['transaction id']['bytes']

	@abc.abstractmethod
	def seconds_elapsed(t=0):
		return struct.pack('>H', t)

	@abc.abstractmethod
	def bootp_flags():
		return b'\x80\x00'

	@abc.abstractmethod
	def client_ip(request):
		return b'\x00\x00\x00\x00'

	@abc.abstractmethod
	def offered_ip(addr):
		return ip_to_bytes(addr)

	@abc.abstractmethod
	def next_server(addr):
		return ip_to_bytes(addr)

	@abc.abstractmethod
	def relay_agent(addr='0.0.0.0'):
		return ip_to_bytes(addr) # Relay agent IP address: 0.0.0.0 because I have no idea what this is heh

	@abc.abstractmethod
	def client_mac(request):
		return request['client mac']['bytes']

	@abc.abstractmethod
	def client_addr_padding():
		return b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   # Client hardware address padding: (Legacy stuff)

	@abc.abstractmethod
	def server_host_name(request):
		return b'\x00' * 64  # Server host name not supplied, so Zero this out

	@abc.abstractmethod
	def magic_cookie():
		return b'\x63\x82\x53\x63'

	@abc.abstractmethod
	def hops(n=0):
		return struct.pack('B', n)

	@abc.abstractmethod
	def identifier(addr):
		"""
		@option: 54
		@link: https://tools.ietf.org/html/rfc2132#section-9.7
		@description: The IP of the server whom is responding to the request
		"""
		return binInt(54)+b'\x04'+int_array_to_hexbytes(ip_to_int(addr))

	@abc.abstractmethod
	def lease_time(t):
		"""
		@option: 54
		@link: https://tools.ietf.org/html/rfc2132#section-9.2
		@description: The time in seconds the lease is valid.
		"""
		
		return binInt(51)+b'\x04'+struct.pack('>I', t)# \x00\x00\xa8\xc0'#+b_fill(binInt(43200), 4) #Lease time (seconds)

	@abc.abstractmethod
	def subnet(subnet):
		"""
		@option: 1
		@link: https://tools.ietf.org/html/rfc2132#section-3.3
		@description: The subnetmask offered to the client.
		"""
		return binInt(1)+b'\x04'+int_array_to_hexbytes(ip_to_int(subnet))

	@abc.abstractmethod
	def broadcast_addr(addr):
		"""
		@option: 28
		@length: 4
		@segments: 2+@length
		@link: https://tools.ietf.org/html/rfc2132#section-5.3
		"""
		broadcast = int_array_to_hexbytes(ip_to_int(addr))
		return binInt(28)+struct.pack('B', len(broadcast))+broadcast

	@abc.abstractmethod
	def dns_servers(*servers):
		"""
		@option: 6
		@length: len(servers)
		@segments: 2+@length
		@link: https://tools.ietf.org/html/rfc2132#section-3.8
		"""
		result = binInt(6)+b'\x08'
		for server in servers:
			result += int_array_to_hexbytes(ip_to_int(server))
		return result

	@abc.abstractmethod
	def tftp_server_name(addr):
		addr = int_array_to_hexbytes(ip_to_int(addr))
		len_of_addr = struct.pack('B', len(addr)+1)
		return binInt(66)+len_of_addr+addr+b'\0' # TFTP Server Name (IP valid)

	@abc.abstractmethod
	def boot_file(filename):
		filename = bytes(filename, 'UTF-8')
		filename_length = struct.pack('B', len(filename)+1)
		return binInt(67)+filename_length+filename+b'\0' # Bootfile name

	@abc.abstractmethod
	def boot_file_prefix(_dir):
		return binInt(210)+struct.pack('B', len(_dir))+bytes(_dir, 'UTF-8') # PXE Path Prefix

	@abc.abstractmethod
	def boot_file_configuration(path):
		return binInt(209)+struct.pack('B', len(path))+bytes(path, 'UTF-8') # PXE Configuration file

	@abc.abstractmethod
	def router(addr):
		"""
		@option: 3
		@link: https://tools.ietf.org/html/rfc2132#section-3.5
		"""
		return binInt(3)+b'\x04'+int_array_to_hexbytes(ip_to_int(addr)) # Router

	@abc.abstractmethod
	def renewal_time(t):
		"""
		@option: 58
		@link: https://tools.ietf.org/html/rfc2132#section-9.11
		"""
		rt = struct.pack('>I', t)
		return binInt(58)+struct.pack('B', len(rt))+rt

	@abc.abstractmethod
	def rebind_time(t):
		"""
		@option: 59
		@link: https://tools.ietf.org/html/rfc2132#section-9.12
		"""
		rt = struct.pack('>I', t)
		return binInt(59)+struct.pack('B', len(rt))+rt # Rebinding Time Value

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
		print(f'[-] Bound to: {{"interface" : "{interface}", "address" : "255.255.255.255", "port" : 67}}')

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

			## Convert and slot the data into the binary map representation
			binary = list(byte_to_bin(data, bin_map=dhcp_packet_struct))

			## Convert the binary representation into the protocol map
			request = {}
			for index in range(len(binary)):
				request[dhcp_protocol[index]] = {'binary' : binary[index], 'bytes' : bin_str_to_byte(binary[index]), 'hex' : None}
				request[dhcp_protocol[index]]['hex'] = bytes_to_hex(request[dhcp_protocol[index]]['bytes'])

			print(f'[+] Packet from: {{"mac": "{human_mac(request["client mac"]["bytes"])}"}}')

			if 'filter_clients' in args and args['filter_clients']:
				if not human_mac(request["client mac"]["bytes"]) in args['filter_clients']:
					print(f'[ ] Request ignored: {{"mac": "{human_mac(request["client mac"]["bytes"])}"}}')
					return

			## Extract the DHCP options from the client
			requests_dhcp_options = request['other']['binary']
			num_of_dhcp_options = ord(bin_str_to_byte([requests_dhcp_options[1]]))
			request['dhcp_options'] = {}

			for item in range(num_of_dhcp_options):
				request['dhcp_options'][item] = { 'binary' : requests_dhcp_options[item],
												  'bytes' : bin_str_to_byte([requests_dhcp_options[item]])}

			## Got all the parsing and processing done.
			## Time ot build a response if the requested packet was DHCP request of some kind.
			packet = b''
			if request['msg type']['bytes'] == b'\x01': # Message type: Boot request (1)
				if request['option 53']['bytes'][-1] == 1: # DHCP Discover
					print(f'[ ] DHCP Discover from: {{"mac": "{human_mac(request["client mac"]["bytes"])}", "type" : "DHCP_DISCOVER"}}')
				if request['option 53']['bytes'][-1] == 3: # DHCP Request
					print(f'[ ] DHCP Request for IP from: {{"mac": "{human_mac(request["client mac"]["bytes"])}", "ip" : "<ignored>", "type" : "DHCP_REQUEST"}}')

				## Check lease time for the specific mac
				## If we don't find a lease, begin the "generate new IP process".
				mac = human_mac(request["client mac"]["bytes"])
				if not (leased_ip := get_lease(mac)):
					# The mac is filtered, and contains a IP
					if args['filter_clients'] and mac in args['filter_clients'] and args['filter_clients'][mac].count('.'):
						leased_ip = bytes(ip_to_int(args['filter_clients'][mac]))
						print(f'[ ] Staticly giving: {{"ip" : "{human_readable(binToObj(leased_ip, int), ".")}", "to" : "{mac}", "type" : "STATIC_DHCP_OFFER"}}')
					else:
						leased_ip = gen_ip(datastore['dhcp']['subnet'], datastore['dhcp']['*ip_uses'])
						print(f'[ ] Dynamically giving: {{"ip" : "{leased_ip}", "to" : "{mac}", "type" : "DYNAMIC_DHCP_OFFER"}}')
					
						if leased_ip:
							datastore['dhcp']['*leases'][mac] = leased_ip
							datastore['dhcp']['*ip_uses'][leased_ip] = mac
						else:
							raise ValueError('Out of IP addresses..') # TODO: make a clean "continue" / "check if old leases expired"

				packet += dhcp_option.dhcp_offer() #Message type: DHCP Offer
				packet += dhcp_option.hardware_type('ethernet')   #Hardware type: Ethernet
				packet += dhcp_option.address_length(6)   #Hardware address length: 6
				packet += dhcp_option.hops(0)   #Hops: 0
				packet += dhcp_option.trasnaction_id(request)   #Transaction ID from the request
				packet += dhcp_option.seconds_elapsed(0)  #Seconds elapsed: 0
				packet += dhcp_option.bootp_flags()   #Bootp flags: 0x8000 (Broadcast) + reserved flags
				packet += dhcp_option.client_ip(request)   # Client IP address: 0.0.0.0
				packet += dhcp_option.offered_ip(leased_ip)   # The IP offered to the client
				packet += dhcp_option.next_server(datastore['dhcp']['pxe_server'])
				packet += dhcp_option.relay_agent(ipaddress.ip_address('0.0.0.0'))
				packet += dhcp_option.client_mac(request) # Client MAC address: 00:26:9e:04:1e:9b
				packet += dhcp_option.client_addr_padding()
				packet += dhcp_option.server_host_name(request)
				packet += b'\x00' * 128 # TODO: Unknown
				packet += dhcp_option.magic_cookie()

				## This is basically what differs in a basic basic DHCP sequence, the message type recieved and matching response.
				if request['option 53']['bytes'][-1] == 1: # DHCP Discover
					print(f'[-] Sending: {{"type" : "OFFER", "to" : "{mac}", "offering" : "{datastore["dhcp"]["*leases"][mac]}"}}')
					packet += dhcp_option.TYPE('OFFER')
				if request['option 53']['bytes'][-1] == 3: # DHCP Request
					print(f'[-] Sending: {{"type" : "PROVIDED", "to" : "{mac}", "offering" : "{datastore["dhcp"]["*leases"][mac]}"}}')
					packet += dhcp_option.TYPE('ACK')
					
				packet += dhcp_option.identifier(datastore['dhcp']['gateway'])
				
				packet += dhcp_option.lease_time(43200)
				packet += dhcp_option.renewal_time(21600)
				packet += dhcp_option.rebind_time(37800)

				packet += dhcp_option.subnet(datastore['dhcp']['subnet'].netmask)
				packet += dhcp_option.broadcast_addr(datastore['dhcp']['subnet'].broadcast_address)
				packet += dhcp_option.router(datastore['dhcp']['gateway'])
				packet += dhcp_option.dns_servers('8.8.8.8', '4.4.4.4')

				## Begin PXE stuff:
				if datastore['dhcp']['pxe_bin']:
					packet += dhcp_option.tftp_server_name(datastore['dhcp']['gateway'])
					packet += dhcp_option.boot_file(datastore['dhcp']['pxe_bin'])
					packet += dhcp_option.boot_file_prefix(datastore['dhcp']['pxe_dir'])
					packet += dhcp_option.boot_file_configuration(datastore['dhcp']['pxe_config'])

				packet += b'\xff'   #End Option
				#packet += b'\x00'*22 # Padding, not sure how much is needed atm but this does it :)

			if len(packet) > 0:
				self.sock.sendto(packet, ('255.255.255.255', 68))

if __name__ == '__main__':
	pxe = dhcp_serve()
	while 1:
		if pxe.poll():
			pxe.parse()
