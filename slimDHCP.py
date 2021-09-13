import sys, struct, json, abc, os, copy, signal, binascii, ipaddress #Python v3.3
import socket, fcntl, ctypes
from select import epoll, EPOLLIN

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_AUXDATA = 8
"""
# Saving this snippet, might come in handy
	s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s < 0) {
		printf("socket failed: %m");
		return -1;
	}
	soc = s;
	if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0)
		printf("setsockopt packet filter failed: %m");

	printf("setsockopt packet filter");

	
	strcpy(ifr.ifr_name, interface);
	if (ioctl(soc, SIOCGIFINDEX, &ifr) < 0) {
		printf("EthRawSockStart(): ioctl() SIOCGIFINDEX failed! error: %d (NIC: %s)",errno,ifr.ifr_name);
		return;
	}

	/* Bind to eth0.50 interface only - this is a private VLAN */

	if (( setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr))) < 0)
	{
		perror("Server-setsockopt() error for SO_BINDTODEVICE");
		printf("%s\n", strerror(errno));
		close(s);
		exit(-1);
	}
	printf("\n Bind to eth0.... \n");
"""

class JSON_Typer(json.JSONEncoder):
	def _encode(self, obj):
		## Workaround to handle keys in the dictionary being bytes() objects etc.
		## Also handles recursive JSON encoding. In case sub-keys are bytes/date etc.
		##
		## README: If you're wondering why we're doing loads(dumps(x)) instad of just dumps(x)
		##         that's because it would become a escaped string unless we loads() it back as
		##         a regular object - before getting passed to the super(JSONEncoder) which will
		##         do the actual JSON encoding as it's last step. All this shananigans are just
		##         to recursively handle different data types within a nested dict/list/X struct.
		if isinstance(obj, dict):
			def check_key(o):
				if type(o) == bytes:
					o = o.decode('UTF-8', errors='replace')
				elif type(o) == set:
					o = json.loads(json.dumps(o, cls=JSON_Typer))
				elif isinstance(o, ipaddress.IPv4Address):
					return str(o)
				elif isinstance(o, ipaddress.IPv4Network):
					return str(o)
				elif getattr(o, "__dump__", None): #hasattr(obj, '__dump__'):
					return o.__dump__()
				return o
			## We'll need to iterate not just the value that default() usually gets passed
			## But also iterate manually over each key: value pair in order to trap the keys.
			
			for key, val in list(obj.items()):
				if isinstance(val, dict):
					val = json.loads(json.dumps(val, cls=JSON_Typer)) # This, is a EXTREMELY ugly hack..
															# But it's the only quick way I can think of to 
															# trigger a encoding of sub-dictionaries. (I'm also very tired, yolo!)
				else:
					val = check_key(val)
				del(obj[key])
				obj[check_key(key)] = val
			return obj
		elif isinstance(obj, ipaddress.IPv4Address):
			return str(obj)
		elif isinstance(obj, ipaddress.IPv4Network):
			return str(obj)
		elif getattr(obj, "__dump__", None): #hasattr(obj, '__dump__'):
			return obj.__dump__()
		elif isinstance(obj, (datetime, date)):
			return obj.isoformat()
		elif isinstance(obj, (custom_class, custom_class_two)):
			return json.loads(json.dumps(obj.dump(), cls=JSON_Typer))
		elif isinstance(obj, (list, set, tuple)):
			r = []
			for item in obj:
				r.append(json.loads(json.dumps(item, cls=JSON_Typer)))
			return r
		else:
			return obj

	def encode(self, obj):
		return super(JSON_Typer, self).encode(self._encode(obj))

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

def hexInt(num):
	""" Converts a int() to hex() representation in bytes() format. """
	return bytearray.fromhex(hex(num)[2:].zfill(2))

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

def save_local_storage(filename, storage):
	with open(filename, 'w') as fh:
		datastore_snapshot = copy.deepcopy(storage)
		fh.write(json.dumps(datastore_snapshot, indent=4, cls=JSON_Typer))

def load_local_storage(filename):
	if not filename or not os.path.isfile(filename): return {}

	with open(filename, 'r') as fh:
		storage = json.load(fh)
		print(f'[-] Loaded cache: {{"type" : "cache", "loaded" : "{args["cache_dir"]}/{args["cache_db"]}"}}')

	for key in list(storage['leases_by_ip'].keys()):
		if key == '<internal self reference>': continue
		if type(key) != ipaddress.IPv4Address:
			storage['leases_by_ip'][ipaddress.ip_address(key)] = storage['leases_by_ip'][key]
			del(storage['leases_by_ip'][key])

	for key, val in list(storage['leases_by_mac'].items()):
		if val == '<internal self reference>' or key == '<internal self reference>': continue
		if type(val) != ipaddress.IPv4Address:
			storage['leases_by_mac'][key] = ipaddress.ip_address(storage['leases_by_mac'][key])

	if type(storage['gateway']) != ipaddress.IPv4Address:
		storage['gateway'] = ipaddress.ip_address(storage['gateway'])

	if type(storage['subnet']) != ipaddress.IPv4Address:
		storage['subnet'] = ipaddress.ip_network(storage['subnet'])

	if type(storage['pxe_server']) != ipaddress.IPv4Address:
		storage['pxe_server'] = ipaddress.ip_address(storage['pxe_server'])

	return storage

def parse_auxillary_data(auxillary_data):
	for message_level, message_type, message_data in auxillary_data:
		if message_level == SOL_PACKET and message_type == PACKET_AUXDATA:
			auxdata = tpacket_auxdata.from_buffer_copy(message_data)
			yield {
				'status' : auxdata.tp_status,
				'len' : auxdata.tp_len,
				'snaplen' : auxdata.tp_snaplen,
				'mac' : auxdata.tp_mac,
				'net' : auxdata.tp_net,
				'vlan' : auxdata.tp_vlan_tci,
				'padding' : auxdata.tp_padding
			}

def mac_to_bytes(mac):
	if not type(mac) == bytes:
		raise ValueError("mac_to_bytes needs bytes as the mac address")
	if not b':' in mac:
		raise ValueError("mac_to_bytes needs : separated mac addresses")
	return b''.join([struct.pack('B', int(mac_part, 16)) for mac_part in mac.split(b':')])

def ethernet(src, dst):
	return mac_to_bytes(dst) + mac_to_bytes(src)

def ipv4(src, dst):
	version_header_length = 0b01000101
	diff_service_field = 0b00010000
	total_length = struct.pack('>h', 330)
	identification = b'\x00\x00'
	flags = 0b01000000
	fragmet_offset = b'\x00'
	ttl = 64
	protocol = 17 # udp
	header_checksum = b'\x39\x94'
	source_address = b''.join([struct.pack('B', int(src_part)) for src_part in src.split('.')])
	destination_address = b''.join([struct.pack('B', int(dst_part)) for dst_part in dst.split('.')])

	return (
		struct.pack('B', version_header_length)
		+ struct.pack('B', diff_service_field)
		+ total_length
		+ identification
		+ struct.pack('B', flags)
		+ fragmet_offset
		+ struct.pack('B', ttl)
		+ struct.pack('B', protocol)
		+ header_checksum
		+ source_address
		+ destination_address
	)

def udp(src=67, dst=68):
	return (
		struct.pack('>h', src)
		+ struct.pack('>h', dst)
		+ struct.pack('>h', 310)
		+ b'\x3f\xa4'
	)

class tpacket_auxdata(ctypes.Structure):
	_fields_ = [
		("tp_status", ctypes.c_uint),
		("tp_len", ctypes.c_uint),
		("tp_snaplen", ctypes.c_uint),
		("tp_mac", ctypes.c_ushort),
		("tp_net", ctypes.c_ushort),
		("tp_vlan_tci", ctypes.c_ushort),
		("tp_padding", ctypes.c_ushort),
	]

## This is a ctype structure that matches the
## requirements to set a socket in promisc mode.
## In all honesty don't know where i found the values :)
class ifreq(ctypes.Structure):
		_fields_ = [("ifr_ifrn", ctypes.c_char * 16),
					("ifr_flags", ctypes.c_short)]

class promisc():
	def __init__(self, s, interface=b'ens33'):
		self.s = s
		self.interface = interface
		self.ifr = ifreq()

	def on(self):
		## -- Set up promisc mode:
		## 

		IFF_PROMISC = 0x100
		SIOCGIFFLAGS = 0x8913
		SIOCSIFFLAGS = 0x8914

		self.ifr.ifr_ifrn = self.interface

		fcntl.ioctl(self.s.fileno(), SIOCGIFFLAGS, self.ifr)
		self.ifr.ifr_flags |= IFF_PROMISC

		fcntl.ioctl(self.s.fileno(), SIOCSIFFLAGS, self.ifr)
		## ------------- DONE

	def off(self):
		## Turn promisc mode off:
		self.ifr.ifr_flags &= ~IFF_PROMISC
		fcntl.ioctl(self.s.fileno(), SIOCSIFFLAGS, self.ifr)
		## ------------- DONE


class dhcp_option(abc.ABCMeta):
	"""
	This class abstracts the build process of using struct.pack() to
	create a structure that looks like: option | length | data
	(length and data is optional, depending on the option used)

	For instance, if building the DHCP Message type "DHCP Offer message", it's a total of 3 bytes for that field.
	Option is required and would be a single byte with the int value 53, length would be 1 and data would be a
	single byte integer of the value 2. That would boild down to:
	
	option | length | data == 53 | 1 | 2 == \x35 | \x01 | \x02

	Each abstract function then returns it's product: \x35\x01\x02
	Which can be used to build a bytes structure ready for client delivery.

	Some functions return 

	"""
	@abc.abstractmethod
	def TYPE(_type):
		dhcp_message_types = {
			'OFFER' : 2,
			'ACK' : 5
		}
		if not _type in dhcp_message_types: raise KeyError('DHCP Message type not defined in dhcp_message_types.')

		"""
		@option: 53
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
	def hardware_address_length(len):
		return b'\x06'

	@abc.abstractmethod
	def trasnaction_id(request):
		return request['transaction id']['bytes']

	@abc.abstractmethod
	def seconds_elapsed(t=0):
		return struct.pack('>H', t)

	@abc.abstractmethod
	def bootp_flags():    #Bootp flags: 0x8000 (Broadcast) + reserved flags
		return b'\x80\x00'

	@abc.abstractmethod
	def client_ip(request): # 0.0.0.0 (We could honor it, but that's a TODO)
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
	def __init__(self, *args, **kwargs):
		if not 'interface' in kwargs:
			raise KeyError('dhcp_server() requires at least a interface=X to be given.')

		## Cache variables:
		self.leases_by_mac = {}
		self.leases_by_ip = {}

		## Update our self.variable = value references.
		for var, val in kwargs.items():
			self.__dict__[var] = val

		with open(f'/sys/class/net/{self.interface}/address', 'r') as fh:
			self.mac = fh.read().strip()

		if self.is_gateway and self.mac not in self.leases_by_mac and self.gateway not in self.leases_by_ip:
			print(f'[-] We are the gateway: {{"gateway" : "{self.gateway}", "mac" : "{self.mac}"}}')
			self.leases_by_ip[self.gateway] = self.mac
			self.leases_by_mac[self.mac] = self.gateway
		else:
			print(f'[-] Gateway MAC unknown: {{"gateway" : "{self.gateway}", "mac" : "unknown"}}')
			self.leases_by_ip[self.gateway] = '00:00:00:00:00:00'
			self.leases_by_mac['00:00:00:00:00:00'] = self.gateway
		
		# https://github.com/Torxed/python-socket/blob/main/pysocket/pysocket.py
		self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
		self.socket.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
		promisciousMode = promisc(self.socket, bytes(kwargs['interface'], 'UTF-8'))
		promisciousMode.on()

		self.main_so_id = self.socket.fileno()
		print(f'[-] Bound to: {{"interface" : "{kwargs["interface"]}", "address" : "255.255.255.255", "port" : 67}}')

		self.pollobj = epoll()
		self.pollobj.register(self.main_so_id, EPOLLIN)

		self.temp = []


	def poll(self, timeout=0.001, fileno=None):
		d = dict(self.pollobj.poll(timeout))
		if fileno: return d[fileno] if fileno in d else None
		return d

	def close(self):
		self.pollobj.unregister(self.main_so_id)
		self.socket.close()

	def get_lease(self, mac):
		if mac in self.leases_by_mac:
			return self.leases_by_mac[mac]
		else:
			return None

	def parse(self):
		# The struct just maps how many bytes (not bits) per section in a DHCP request.
		# A graphic overview can be found here: https://tools.ietf.org/html/rfc2131#section-2
		dhcp_packet_struct = [1, 1, 1, 1, 4, 2, 2, 4, 4, 4, 4, 6, 10, 64, 128, 4, 3]
		# We then use that struct map to place the values into a dictionary with these keys (in order):
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
			data, auxillary_data_raw, flags, addr = self.socket.recvmsg(65535, socket.CMSG_LEN(4096))
			
			if not data:
				return

			auxillary_data = []
			if auxillary_data_raw:
				auxillary_data = list(parse_auxillary_data(auxillary_data_raw))[0]

			ethernet_data = data[0:14]
			ethernet_segments = struct.unpack("!6s6s2s", ethernet_data)

			mac_dest, mac_source = (binascii.hexlify(mac) for mac in ethernet_segments[:2])
			mac_source = b':'.join(mac_source[i:i+2] for i in range(0, len(mac_source), 2))
			mac_dest = b':'.join(mac_dest[i:i+2] for i in range(0, len(mac_dest), 2))
			frame_type = binascii.hexlify(ethernet_segments[2])
			
			ip = data[14:34]
			ip_segments = struct.unpack("!12s4s4s", ip)

			ip_source, ip_dest = (socket.inet_ntoa(section) for section in ip_segments[1:3])

			udp_data = data[34:42]
			udp_segments = struct.unpack("!hhh2s", udp_data)
			source_port, destination_port, udp_payload_len, udp_checksum = udp_segments

			# IPv4 == \x08\x00
			if frame_type != b'0800':
				return

			if not mac_dest == b'ff:ff:ff:ff:ff:ff':
				# We only accept broadcasts
				return

			if destination_port != 67:
				return

			# print('MAC Source:', mac_source)
			# print('MAC Dest:', mac_dest)
			# print('Frame Type:', frame_type)
			# print(auxillary_data)
			# print(binascii.hexlify(data))

			# print('IP Source:', ip_source)
			# print('IP Dest:', ip_dest)

			# print('UDP:', source_port, destination_port)

			## Convert and slot the data into the binary map representation
			binary = list(byte_to_bin(data[42:], bin_map=dhcp_packet_struct))

			## Convert the binary representation into the protocol map
			request = {}
			for index in range(len(binary)):
				request[dhcp_protocol[index]] = {'binary' : binary[index], 'bytes' : bin_str_to_byte(binary[index]), 'hex' : None}
				request[dhcp_protocol[index]]['hex'] = bytes_to_hex(request[dhcp_protocol[index]]['bytes'])

			print(f'[+] Packet from: {{"mac": "{human_mac(request["client mac"]["bytes"])}"}}')

			## Check if we've white listed clients,
			## and if so, check if this client isn't allowed and return nothing on the cable.
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
			if request['msg type']['bytes'][-1] == 1: # Message type: Boot request (1)
				if request['option 53']['bytes'][-1] == 1: # DHCP Discover
					print(f'[ ] DHCP Discover from: {{"mac": "{human_mac(request["client mac"]["bytes"])}", "type" : "DHCP_DISCOVER"}}')
				if request['option 53']['bytes'][-1] == 3: # DHCP Request
					print(f'[ ] DHCP Request for IP from: {{"mac": "{human_mac(request["client mac"]["bytes"])}", "ip" : "<ignored>", "type" : "DHCP_REQUEST"}}')

				## Check lease time for the specific mac
				## If we don't find a lease, begin the "generate new IP process".
				mac = human_mac(request["client mac"]["bytes"])
				if not (leased_ip := self.get_lease(mac)):
					# The mac is filtered, and contains a static IP lease definition
					if args['filter_clients'] and mac in args['filter_clients'] and args['filter_clients'][mac].count('.'):
						leased_ip = ipaddress.ip_address(args['filter_clients'][mac])
						print(f'[ ] Staticly giving: {{"ip" : "{leased_ip}", "to" : "{mac}", "type" : "STATIC_DHCP_OFFER"}}')
					# Otherwise, generate a IP from the total pool of available IP's
					else:
						leased_ip = gen_ip(self.subnet, self.leases_by_ip)
						print(f'[ ] Dynamically giving: {{"ip" : "{leased_ip}", "to" : "{mac}", "type" : "DYNAMIC_DHCP_OFFER"}}')
					
					if leased_ip:
						self.leases_by_mac[mac] = leased_ip
						self.leases_by_ip[leased_ip] = mac
					else:
						raise ValueError('TODO: Out of IP addresses..') # TODO: make a clean "continue" / "check if old leases expired"
				# There was a pre-existing lease, using that lease:
				else:
					print(f'[ ] Giving cached: {{"ip" : "{leased_ip}", "to" : "{mac}", "type" : "CACHED_DHCP_OFFER"}}')

				# Assemble the packet headers
				packet += ethernet(src=b'00:51:82:11:22:00', dst=mac_source) + b'\x81\x00'
				packet += struct.pack('>h', 0b0000000000000010) + b'\x08\x00'# vlan(struct.pack('>h', 0b0000000000000010) + b'\x08\x00')
				packet += ipv4(src='172.23.0.1', dst='255.255.255.255')
				packet += udp(src=67, dst=68)

				# Assemble the DHCP specific payload
				packet += dhcp_option.dhcp_offer()
				packet += dhcp_option.hardware_type('ethernet')
				packet += dhcp_option.hardware_address_length(6)
				packet += dhcp_option.hops(0)
				packet += dhcp_option.trasnaction_id(request)
				packet += dhcp_option.seconds_elapsed(0)
				packet += dhcp_option.bootp_flags()
				packet += dhcp_option.client_ip(request)
				packet += dhcp_option.offered_ip(leased_ip)
				packet += dhcp_option.next_server(self.pxe_server) # 0.0.0.0 == None
				packet += dhcp_option.relay_agent(ipaddress.ip_address('0.0.0.0'))
				packet += dhcp_option.client_mac(request)
				packet += dhcp_option.client_addr_padding()
				packet += dhcp_option.server_host_name(request)
				packet += b'\x00' * 128 # TODO: Unknown
				packet += dhcp_option.magic_cookie()

				## This is basically what differs in a basic basic DHCP sequence,
				## the message type recieved and matching response. At least for a basic IP request/handshake.
				if request['option 53']['bytes'][-1] == 1: # DHCP Discover
					print(f'[-] Sending: {{"type" : "OFFER", "to" : "{mac}", "offering" : "{self.leases_by_mac[mac]}"}}')
					packet += dhcp_option.TYPE('OFFER')
				if request['option 53']['bytes'][-1] == 3: # DHCP Request
					print(f'[-] Sending: {{"type" : "PROVIDED", "to" : "{mac}", "offering" : "{self.leases_by_mac[mac]}"}}')
					packet += dhcp_option.TYPE('ACK')
				
				# Slap on the clients trasnacation identifier so it knows
				# we responded to the request and not some other request it made.	
				packet += dhcp_option.identifier(self.gateway)
				
				# We don't honor these, so we're generous with them:
				packet += dhcp_option.lease_time(43200)
				packet += dhcp_option.renewal_time(21600)
				packet += dhcp_option.rebind_time(37800)

				# And the IP, subnet, router(gateway) and DNS information.
				packet += dhcp_option.subnet(self.subnet.netmask)
				packet += dhcp_option.broadcast_addr(self.subnet.broadcast_address)
				packet += dhcp_option.router(self.gateway)
				packet += dhcp_option.dns_servers(*self.dns_servers)

				# If we have a PXE binary to deliver, add the appropriate options to the request:
				if self.pxe_bin:
					packet += dhcp_option.tftp_server_name(self.gateway)
					packet += dhcp_option.boot_file(self.pxe_bin)
					packet += dhcp_option.boot_file_prefix(self.pxe_dir)
					packet += dhcp_option.boot_file_configuration(self.pxe_config)

				packet += b'\xff'   #End Option

			if len(packet) > 0:
				import array
				socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL)
				print(auxillary_data_raw, auxillary_data)
				self.socket.sendmsg([packet], auxillary_data_raw, flags, addr)

				if self.cache_db:
					save_local_storage(self.cache_dir + '/' + self.cache_db, {**self.__dict__, 'socket' : None, 'pollobj' : None})

if __name__ == '__main__':
	def sig_handler(signal, frame):
		dhcp.close()
		exit(0)
	signal.signal(signal.SIGINT, sig_handler)

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
	
	if not 'cache_dir' in args: args['cache_dir'] = './'
	if not 'cache_db' in args: args['cache_db'] = None
	args = {**load_local_storage(f"{args['cache_dir']}/{args['cache_db']}"), **args}

	if not 'subnet' in args: args['subnet'] = '192.168.1.0'
	if not 'netmask' in args: args['netmask'] = '255.255.255.0' # Optional, if it's given on the subnet definition.
	if not 'gateway' in args: args['gateway'] = None # Takes the first host of the subnet by default
	if not 'is_gateway' in args: args['is_gateway'] = False
	if not 'dns_servers' in args: args['dns_servers'] = ('8.8.8.8', '4.4.4.4')
	if not 'pxe_bin' in args: args['pxe_bin'] = None # Point toward a efi file, for instance: '/ipxe.efi'
	if not 'pxe_dir' in args: args['pxe_dir'] = './'# './pxe_files'
	if not 'pxe_config' in args: args['pxe_config'] = 'loader/loader.conf'
	if not 'pxe_server' in args:
		if args['pxe_bin']:
			args['pxe_server'] = args['gateway']
		else:
			args['pxe_server'] = '0.0.0.0'
	if not 'filter_clients' in args: args['filter_clients'] = '{}' # JSON structure of clients


	## Convert arguments to workable elements:
	if type(args['dns_servers']) == str:
		args['dns_servers'] = json.loads(args['dns_servers'])
	if type(args['subnet']) == str:
		## Append the netmask/cidr on to the subnet definition if not already given.
		if not '/' in args['subnet']: args['subnet'] = f"{args['subnet']}/{args['netmask']}"
		args['subnet'] = ipaddress.ip_network(args['subnet'])
	if type(args['pxe_server']) == str:
		args['pxe_server'] = ipaddress.ip_address(args['pxe_server'])

	if type(args['filter_clients']) == str:
		args['filter_clients'] = json.loads(args['filter_clients'])

	# Designate a gateway if none was given, take the first host of our subnet element:
	if not args['gateway']:
		for host in args['subnet'].hosts():
			args['gateway'] = host
			break

	dhcp = dhcp_serve(**args)
	while 1:
		if dhcp.poll():
			dhcp.parse()
