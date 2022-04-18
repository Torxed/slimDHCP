
# https://www.netmanias.com/en/post/techdocs/6000/dhcp-network-protocol/understanding-dhcp-relay-agents

import sys, struct, json, abc, os, copy, signal
import socket, fcntl
from select import epoll, EPOLLIN
import ctypes.util
import ctypes
import pydantic
import ipaddress
import argparse
import urllib.parse
import urllib.request
import pathlib
import binascii
import logging
from typing import Optional, Dict, Union, List, Tuple, Any, Type

# Static values to subscribe to aux data on individual packets
ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_AUXDATA = 8

class struct_sockaddr(ctypes.Structure):
	 _fields_ = [
		('sa_family', ctypes.c_ushort),
		('sa_data', ctypes.c_byte * 14),]

class struct_sockaddr_in(ctypes.Structure):
	_fields_ = [
		('sin_family', ctypes.c_ushort),
		('sin_port', ctypes.c_uint16),
		('sin_addr', ctypes.c_byte * 4)]

class struct_sockaddr_in6(ctypes.Structure):
	_fields_ = [
		('sin6_family', ctypes.c_ushort),
		('sin6_port', ctypes.c_uint16),
		('sin6_flowinfo', ctypes.c_uint32),
		('sin6_addr', ctypes.c_byte * 16),
		('sin6_scope_id', ctypes.c_uint32)]

class union_ifa_ifu(ctypes.Union):
	_fields_ = [
		('ifu_broadaddr', ctypes.POINTER(struct_sockaddr)),
		('ifu_dstaddr', ctypes.POINTER(struct_sockaddr)),]

class struct_ifaddrs(ctypes.Structure):
	pass

def ifap_iter(ifap):
	ifa = ifap.contents
	while True:
		yield ifa
		if not ifa.ifa_next:
			break
		ifa = ifa.ifa_next.contents

def getfamaddr(sa):
	family = sa.sa_family
	addr = None
	if family == socket.AF_INET:
		sa = ctypes.cast(ctypes.pointer(sa), ctypes.POINTER(struct_sockaddr_in)).contents
		addr = socket.inet_ntop(family, sa.sin_addr)
	elif family == socket.AF_INET6:
		sa = ctypes.cast(ctypes.pointer(sa), ctypes.POINTER(struct_sockaddr_in6)).contents
		addr = socket.inet_ntop(family, sa.sin6_addr)
	return family, addr

class NetworkInterface(object):
	def __init__(self, name):
		self.name = name
		self.index = libc.if_nametoindex(name)
		self.addresses = {}

	def __str__(self):
		return "%s [index=%d, IPv4=%s, IPv6=%s]" % (
			self.name, self.index,
			self.addresses.get(socket.AF_INET),
			self.addresses.get(socket.AF_INET6))

def get_network_interfaces():
	ifap = ctypes.POINTER(struct_ifaddrs)()
	result = libc.getifaddrs(ctypes.pointer(ifap))
	if result != 0:
		raise OSError(get_errno())
	del result
	try:
		retval = {}
		for ifa in ifap_iter(ifap):
			name = ifa.ifa_name
			if not name.decode('UTF-8') in retval:
				retval[name.decode('UTF-8')] = {}
			
			try:
				family, addr = getfamaddr(ifa.ifa_addr.contents)
				family, subnet = getfamaddr(ifa.ifa_netmask.contents)
			except ValueError:
				family, addr, subnet = None, None, None

			if addr:
				# TODO: Does not support IPv6.
				# the addr is/can be IPv6, but the ipaddress.ip_network() fails
				try:
					retval[name.decode('UTF-8')][ipaddress.ip_address(addr)] = ipaddress.ip_network(f"{ipaddress.ip_address(addr)}/{subnet}", strict=False)
				except ValueError:
					pass
		return retval
	finally:
		libc.freeifaddrs(ifap)

struct_ifaddrs._fields_ = [
	('ifa_next', ctypes.POINTER(struct_ifaddrs)),
	('ifa_name', ctypes.c_char_p),
	('ifa_flags', ctypes.c_uint),
	('ifa_addr', ctypes.POINTER(struct_sockaddr)),
	('ifa_netmask', ctypes.POINTER(struct_sockaddr)),
	('ifa_ifu', union_ifa_ifu),
	('ifa_data', ctypes.c_void_p),]

libc = ctypes.CDLL(ctypes.util.find_library('c'))


class Journald:
	@staticmethod
	def log(message :str, level :int = logging.DEBUG) -> None:
		try:
			import systemd.journal  # type: ignore
		except ModuleNotFoundError:
			return None

		log_adapter = logging.getLogger('archinstall')
		log_fmt = logging.Formatter("[%(levelname)s]: %(message)s")
		log_ch = systemd.journal.JournalHandler()
		log_ch.setFormatter(log_fmt)
		log_adapter.addHandler(log_ch)
		log_adapter.setLevel(logging.DEBUG)

		log_adapter.log(level, message)

def supports_color() -> bool:
	"""
	Return True if the running system's terminal supports color,
	and False otherwise.
	"""
	supported_platform = sys.platform != 'win32' or 'ANSICON' in os.environ

	# isatty is not always implemented, #6223.
	is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
	return supported_platform and is_a_tty

# Heavily influenced by: https://github.com/django/django/blob/ae8338daf34fd746771e0678081999b656177bae/django/utils/termcolors.py#L13
# Color options here: https://askubuntu.com/questions/528928/how-to-do-underline-bold-italic-strikethrough-color-background-and-size-i
def stylize_output(text: str, *opts :str, **kwargs) -> str:
	"""
	Adds styling to a text given a set of color arguments.
	"""
	opt_dict = {'bold': '1', 'italic': '3', 'underscore': '4', 'blink': '5', 'reverse': '7', 'conceal': '8'}
	colors = {
		'black' : '0',
		'red' : '1',
		'green' : '2',
		'yellow' : '3',
		'blue' : '4',
		'magenta' : '5',
		'cyan' : '6',
		'white' : '7',
		'orange' : '8;5;208',    # Extended 256-bit colors (not always supported)
		'darkorange' : '8;5;202',# https://www.lihaoyi.com/post/BuildyourownCommandLinewithANSIescapecodes.html#256-colors
		'gray' : '8;5;246',
		'darkgray' : '8;5;240',
		'lightgray' : '8;5;256'
	}
	foreground = {key: f'3{colors[key]}' for key in colors}
	background = {key: f'4{colors[key]}' for key in colors}
	reset = '0'

	code_list = []
	if text == '' and len(opts) == 1 and opts[0] == 'reset':
		return '\x1b[%sm' % reset

	for k, v in kwargs.items():
		if k == 'fg':
			code_list.append(foreground[str(v)])
		elif k == 'bg':
			code_list.append(background[str(v)])

	for o in opts:
		if o in opt_dict:
			code_list.append(opt_dict[o])

	if 'noreset' not in opts:
		text = '%s\x1b[%sm' % (text or '', reset)

	return '%s%s' % (('\x1b[%sm' % ';'.join(code_list)), text or '')


def log(*args :str, **kwargs :Union[str, int, Dict[str, Union[str, int]]]) -> None:
	string = orig_string = ' '.join([str(x) for x in args])

	# Attempt to colorize the output if supported
	# Insert default colors and override with **kwargs
	if supports_color():
		kwargs = {'fg': 'white', **kwargs}
		string = stylize_output(string, **kwargs)

	Journald.log(string, level=int(str(kwargs.get('level', logging.INFO))))

	# Finally, print the log unless we skipped it based on level.
	# We use sys.stdout.write()+flush() instead of print() to try and
	# fix issue #94
	if kwargs.get('level', logging.INFO) != logging.DEBUG or storage['arguments'].get('verbose', False):
		sys.stdout.write(f"{string}\n")
		sys.stdout.flush()

def get_ip_address(ifname):
	if not type(ifname) == bytes:
		ifname = bytes(ifname, 'UTF-8')
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	try:
		return ipaddress.IPv4Address(
			socket.inet_ntoa(fcntl.ioctl(
				s.fileno(),
				0x8915,  # SIOCGIFADDR
				struct.pack('256s', ifname[:15])
			)[20:24])
		)
	except:
		pass

	return None

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

	for i in bs:
		raw.append('{0:b}'.format(i).zfill(8))

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

def bytes_to_ip(b):
	s = ''
	for i in b:
		s += '{:d}.'.format(i) # Int -> INT.
	return ipaddress.ip_address(s[:-1])

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
		if str(host) not in exludes:
			return host

def bytes_to_mac(obj):
	if type(obj) == bytes:
		return ':'.join([item[2:].zfill(2) for item in binToObj(obj, hex)])
	else:
		raise KeyError('Not yet implemented: bytes_to_mac(hex)')

def human_readable(l, separator):
	return f"{separator}".join([str(x) for x in l])

def ip_to_bytes(ip_obj):
	if type(ip_obj) == str:
		ip_obj = ipaddress.ip_address(ip_obj)
	return struct.pack('>I', int(ip_obj))

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
	if type(mac) != bytes:
		mac = bytes(mac, 'UTF-8')
	
	if b':' not in mac:
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
	source_address = b''.join([struct.pack('B', int(src_part)) for src_part in str(src).split('.')])
	destination_address = b''.join([struct.pack('B', int(dst_part)) for dst_part in str(dst).split('.')])

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
	IFF_PROMISC = 0x100
	SIOCGIFFLAGS = 0x8913
	SIOCSIFFLAGS = 0x8914

	def __init__(self, s, interface=b'ens33'):
		self.s = s
		self.fileno = s.fileno()
		self.interface = interface
		self.ifr = ifreq()

	def on(self):
		## -- Set up promisc mode:
		## 


		self.ifr.ifr_ifrn = self.interface

		fcntl.ioctl(self.fileno, self.SIOCGIFFLAGS, self.ifr)
		self.ifr.ifr_flags |= self.IFF_PROMISC

		fcntl.ioctl(self.fileno, self.SIOCSIFFLAGS, self.ifr)
		## ------------- DONE

	def off(self):
		## Turn promisc mode off:
		self.ifr.ifr_flags &= ~self.IFF_PROMISC
		fcntl.ioctl(self.fileno, self.SIOCSIFFLAGS, self.ifr)
		## ------------- DONE

class dhcp_fields(abc.ABCMeta):
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
	def transaction_id(identifier :int):
		return struct.pack('>I', identifier)

	@abc.abstractmethod
	def seconds_elapsed(t=0):
		return struct.pack('>H', t)

	@abc.abstractmethod
	def bootp_flags(flags :bytes):
		return flags

	@abc.abstractmethod
	def client_ip(client_ip :ipaddress.IPv4Address): # TODO: We won't honor any requested
		#if request['client ip']['bytes'] != b'\x00\x00\x00\x00':
		#	print('Client is asking for IP:', [bytes_to_ip(request['client ip']['bytes'])], 'in leases', server_instance.leases_by_ip)
		#	if (ip := bytes_to_ip(request['client ip']['bytes'])) in server_instance.leases_by_ip:
		#		print('IP was in leases')
		#		if (mac := bytes_to_mac(request['client mac']['bytes'])) in server_instance.leases_by_mac:
		#			print(f"IP {ip} and MAC {mac} was identified as a previous lease: {server_instance.leases_by_mac[mac]}")
		#			#if ip == server_instance.leases_by_mac[mac]:
		return b'\x00\x00\x00\x00'

	@abc.abstractmethod
	def offered_ip(addr):
		return ip_to_bytes(str(addr))

	@abc.abstractmethod
	def next_server(addr):
		return ip_to_bytes(str(addr))

	@abc.abstractmethod
	def relay_agent(addr='0.0.0.0'):
		return ip_to_bytes(str(addr)) # Relay agent IP address: 0.0.0.0 because I have no idea what this is heh

	@abc.abstractmethod
	def client_mac(address):
		return mac_to_bytes(address)

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

class NonIPv4Frame(BaseException):
	pass
class NonBroadcastFrame(BaseException):
	pass
class NonDHCPFrame(BaseException):
	pass
class InvalidFrameLength(BaseException):
	pass

class AuxillaryItem(pydantic.BaseModel):
	status: Any
	length: Any
	snap_length: Any
	mac: Any
	net: Any
	vlan: Any
	padding: Any

# class AuxillaryList(pydantic.BaseModel):
# 	items: List[AuxillaryItem] = []

# 	@pydantic.validator("*", pre=True)
# 	def convert(cls, value):
# 		print(value)
# 		result = []
# 		for message_level, message_type, message_data in auxillary_data:
# 			if message_level == SOL_PACKET and message_type == PACKET_AUXDATA:
# 				auxdata = tpacket_auxdata.from_buffer_copy(message_data)
# 				result.append(
# 					AuxillaryItem({
# 						'status' : auxdata.tp_status,
# 						'length' : auxdata.tp_len,
# 						'snap_length' : auxdata.tp_snaplen,
# 						'mac' : auxdata.tp_mac,
# 						'net' : auxdata.tp_net,
# 						'vlan' : auxdata.tp_vlan_tci,
# 						'padding' : auxdata.tp_padding
# 					})
# 				)
# 		return result

class Ethernet_IPv4:
	pass

class Ethernet_Unknown:
	pass

class Ethernet(pydantic.BaseModel):
	source: pydantic.constr(to_lower=True, min_length=17, max_length=17)
	destination: pydantic.constr(to_lower=True, min_length=17, max_length=17)
	payload_type: Union[Type[Ethernet_IPv4], Type[Ethernet_Unknown]]

	class Config:
		arbitrary_types_allowed = True
		smart_union = True

	@pydantic.validator("payload_type", pre=True)
	def convert(cls, value):
		# IPv4 == \x08\x00
		if value == b'0800':
			return Ethernet_IPv4
		return Ethernet_Unknown

class UDP(pydantic.BaseModel):
	source_port: int
	destination_port: int
	length: int
	checksum: Any

class IPv4(pydantic.BaseModel):
	source: ipaddress.IPv4Network
	destination: ipaddress.IPv4Network
	payload: UDP

class DHCPBootRequest(bytes):
	@classmethod
	def __get_validators__(cls):
		yield cls.validator
	
	@classmethod
	def validator(cls, data: bytes) -> 'DHCPBootRequest':
		if (data := struct.unpack('B', data)[0]) == 1: # Boot request (1)
			return cls

	# Ignored
	def __repr__(self):
		return 'DHCPBootRequest'

	# Ignored
	def __str__(self):
		return 'DHCPBootRequest'

class HardwareType(bytes):
	@classmethod
	def __get_validators__(cls):
		yield cls.validator
	
	@classmethod
	def validator(cls, data: bytes) -> 'HardwareType':
		if (data := struct.unpack('B', data)[0]) == 1: # Ethernet
			return Ethernet

class ByteToInt(bytes):
	@classmethod
	def __get_validators__(cls):
		yield cls.validator
	
	@classmethod
	def validator(cls, data: bytes) -> int:
		return struct.unpack('B', data)[0]

class BytesToInt(bytes):
	@classmethod
	def __get_validators__(cls):
		yield cls.validator
	
	@classmethod
	def validator(cls, data: bytes) -> int:
		return struct.unpack('i', data)[0]

class BytesToShort(bytes):
	@classmethod
	def __get_validators__(cls):
		yield cls.validator
	
	@classmethod
	def validator(cls, data: bytes) -> int:
		return struct.unpack('h', data)[0]

class BytesToIP(bytes):
	@classmethod
	def __get_validators__(cls):
		yield cls.validator
	
	@classmethod
	def validator(cls, data: bytes) -> ipaddress.IPv4Address:
		s = ''
		for i in data:
			s += '{:d}.'.format(i) # Int -> INT.
		return ipaddress.ip_address(s[:-1])

class BytesToMAC(bytes):
	@classmethod
	def __get_validators__(cls):
		yield cls.validator
	
	@classmethod
	def validator(cls, data: bytes) -> str:
		return ':'.join([item[2:].zfill(2) for item in binToObj(data, hex)])

class BytesToUTF8String(bytes):
	@classmethod
	def __get_validators__(cls):
		yield cls.validator
	
	@classmethod
	def validator(cls, data: bytes) -> str:
		return data.strip(b'\x00').decode('UTF-8')

class DHCPMessageType(pydantic.BaseModel):
	data: int
	binary: List[str]

	@pydantic.validator("data", pre=True)
	def validator(cls, value):
		return struct.unpack('B', value)[0]

	@property
	def discover(self):
		if self.data == 1:
			return True

	@property
	def offer(self):
		if self.data == 2:
			return True

	@property
	def request(self):
		if self.data == 3:
			return True

	@property
	def decline(self):
		if self.data == 4:
			return True

	@property
	def acknowledgement(self):
		if self.data == 5:
			return True

	@property
	def negative_acknowledgement(self):
		if self.data == 6:
			return True

	@property
	def release(self):
		if self.data == 7:
			return True

	@property
	def informational(self):
		if self.data == 8:
			return True

class DHCPOPtions(pydantic.BaseModel):
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
	option_53: DHCPMessageType

	@pydantic.validator("*", pre=True)
	def validator(cls, value):
		return value

class DHCPOptionsParser(bytes):
	@classmethod
	def __get_validators__(cls):
		yield cls.validator
	
	@classmethod
	def validator(cls, raw_data: bytes) -> DHCPOPtions:
		# Build the remaining DHCP options by checking type, length and structuring data.
		pos = 0
		options = {}
		while pos < len(raw_data) and pos <= 312:
			option = raw_data[pos]
			if option == 255: # End
				break
			length = raw_data[pos+1]
			if pos + 2 + length > len(raw_data):
				# out of bounds check
				break
			data = raw_data[pos+2:pos+2+length]
			pos += 2 + length

			options[f"option_{option}"] = {'binary' : byte_to_bin(data), 'data' : data}

		return DHCPOPtions(**options)

class DHCPRequest(pydantic.BaseModel):
	message_type: Union[DHCPBootRequest]
	hardware_type: HardwareType
	hardware_addr_len: ByteToInt
	hops: ByteToInt
	transaction_id: BytesToInt
	elapsed_time: BytesToShort
	bootp_flags: bytes
	client_ip: BytesToIP
	client_assigned_ip: BytesToIP
	server_ip: BytesToIP
	relay_agent: BytesToIP
	client_mac: BytesToMAC
	#client_padding: bytes
	server_hostname: BytesToUTF8String
	boot_file: BytesToUTF8String
	magic_cookie: bool
	options: DHCPOptionsParser
	raw_data: bytes

	@pydantic.validator("magic_cookie", pre=True)
	def magic_cookie_check(cls, data):
		if data != b'c\x82Sc':
			raise ValueError("Incorrect magic cookie")
		return True

	# @pydantic.validator("message_type", pre=True)
	# def convert(cls, data):
	# 	print(struct.unpack('B', data))
	# 	if (message_type := struct.unpack('B', data)[0]) == 1: # Boot request (1)
	# 		return type(DHCPRequestType())

class Frame(pydantic.BaseModel):
	server: 'DHCPServer'
	request: DHCPRequest
	auxillary_data: List[AuxillaryItem]
	auxillary_data_raw: List[Tuple[int, int, bytes]]
	flags: int
	addr: Tuple[str, int, int, int, bytes]
	processed: bool = False

	class Config:
		arbitrary_types_allowed = True

	@pydantic.validator("request", pre=True)
	def convert(cls, data):
		if len(data) < 312 or len(data) > 65535:
			raise InvalidFrameLength

		if len(data) < 42:
			# We need at least 42 bytes to grab the IP headers
			raise InvalidFrameLength

		if cls.ethernet(data).payload_type != Ethernet_IPv4:
			raise NonIPv4Frame
		
		if cls.ethernet(data).destination != 'ff:ff:ff:ff:ff:ff':
			# We only accept broadcasts
			raise NonBroadcastFrame

		if cls.ip(data).payload.destination_port != 67:
			raise NonDHCPFrame

		# The struct just maps how many bytes (not bits) per section in a DHCP request.
		# A graphic overview can be found here: https://tools.ietf.org/html/rfc2131#section-2
		dhcp_packet_struct = [1, 1, 1, 1, 4, 2, 2, 4, 4, 4, 4, 6, 10, 64, 128, 4, 312]

		# We then use that struct map to place the values into a dictionary with these keys (in order):
		dhcp_protocol = [
			'message_type', 'hardware_type', 'hardware_addr_len', 'hops',
			 'transaction_id',
			 'elapsed_time', 'bootp_flags',
			 'client_ip',
			 'client_assigned_ip',
			 'server_ip',
			 'relay_agent',
			 'client_mac',
			 'client_padding',
			 'server_hostname',
			 'boot_file',
			 'magic_cookie',
			 'options'
		]

		binary = list(byte_to_bin(data[42:], bin_map=dhcp_packet_struct))

		request = {}
		for index, frame_section_length in enumerate(dhcp_packet_struct):
			previous = sum(dhcp_packet_struct[:index])
			binary_representation = binary[previous:previous+dhcp_packet_struct[index]]
			bytes_string = bin_str_to_byte(binary_representation)

			request[dhcp_protocol[index]] = {
				'binary' : binary_representation,
				'bytes' : bytes_string,
				'hex' : bytes_to_hex(bytes_string)
			}

		#for index in range(len(binary)):
		#	request[dhcp_protocol[index]] = {'binary' : binary[index], 'bytes' : bin_str_to_byte(binary[index]), 'hex' : None}
		#	request[dhcp_protocol[index]]['hex'] = bytes_to_hex(request[dhcp_protocol[index]]['bytes'])

		request = DHCPRequest(
			**{
				key: value['bytes'] for key, value in request.items() if key != 'client_padding'
			},
			raw_data=data
		)

		log(request, fg="yellow", level=logging.INFO)

		return request

	def response(self):
		return FrameResponse(frame=self)

	def ethernet(data):
		ethernet_segments = struct.unpack("!6s6s2s", data[0:14])
		mac_dest, mac_source = (binascii.hexlify(mac) for mac in ethernet_segments[:2])
		return Ethernet(
			source=':'.join(mac_source[i:i+2].decode('UTF-8') for i in range(0, len(mac_source), 2)),
			destination=':'.join(mac_dest[i:i+2].decode('UTF-8') for i in range(0, len(mac_dest), 2)),
			payload_type=binascii.hexlify(ethernet_segments[2])
		)

	@property
	def Ethernet(self):
		return Frame.ethernet(self.request.raw_data)

	def ip(data):
		ip_segments = struct.unpack("!12s4s4s", data[14:34])

		ip_source, ip_dest = [
			ipaddress.ip_address(x) for x in (
				socket.inet_ntoa(section) for section in ip_segments[1:3]
			)
		]

		source_port, destination_port, udp_payload_len, udp_checksum = struct.unpack("!hhh2s", data[34:42])

		udp_payload = UDP(source_port=source_port, destination_port=destination_port, length=udp_payload_len, checksum=udp_checksum)
		ip_frame = IPv4(source=ip_source, destination=ip_dest, payload=udp_payload)

		return ip_frame

	@property
	def IPv4(self):
		return Frame.ip(self.request.raw_data)

class DHCPResponse(pydantic.BaseModel):
	request_frame: Frame
	data: bytes

class FrameResponse(pydantic.BaseModel):
	frame: DHCPResponse

	@pydantic.validator("frame", pre=True)
	def validator(cls, frame) -> DHCPResponse:
		# Assemble the packet headers
		packet = b''
		packet += ethernet(src=frame.server.mac, dst='ff:ff:ff:ff:ff:ff')
		if frame.auxillary_data[0].vlan:
			packet += b'\x81\x00' # Ethernet frame type is 802.1Q VLAN (0x8100)
			packet += struct.pack('>H', frame.auxillary_data[0].vlan)
		
		# Payload to Ethernet/VLAN frame is IPv4
		packet += b'\x08\x00'
		packet += ipv4(src=list(frame.server.ip)[0], dst='255.255.255.255')
		packet += udp(src=67, dst=68)

		return DHCPResponse(request_frame=frame, data=packet)

		# Assemble the DHCP specific payload
		packet += dhcp_fields.dhcp_offer()
		packet += dhcp_fields.hardware_type('ethernet')
		packet += dhcp_fields.hardware_address_length(6)
		packet += dhcp_fields.hops(frame.request.hops)
		packet += dhcp_fields.transaction_id(frame.request.transaction_id)
		packet += dhcp_fields.seconds_elapsed(0)
		# https://www.ietf.org/rfc/rfc2131.txt
		# page 10:
		#
		# To work around some clients that cannot accept IP unicast datagrams
		# before the TCP/IP software is configured ...
		# [Unicast must not be used]
		if not int(bin(frame.request.bootp_flags[0])[2:][0]):
			packet += dhcp_fields.bootp_flags(b'\x00\x00')
		else:
			packet += dhcp_fields.bootp_flags(b'\x80\x00')
		packet += dhcp_fields.client_ip(frame.request.client_ip)
		packet += dhcp_fields.offered_ip('192.168.5.20')
		if frame.server.configuration.dhcp.pxe:
			packet += dhcp_fields.next_server(frame.server.configuration.dhcp.pxe.next_server)
		else:
			packet += dhcp_fields.next_server(ipaddress.ip_address('0.0.0.0'))
		packet += dhcp_fields.relay_agent(frame.request.relay_agent)
		packet += dhcp_fields.client_mac(frame.Ethernet.source)
		packet += dhcp_fields.client_addr_padding()
		packet += dhcp_fields.server_host_name(frame.request.server_hostname)
		packet += b'\x00' * 128 # TODO: Unknown
		packet += dhcp_fields.magic_cookie()

		"""
		## This is basically what differs in a basic basic DHCP sequence,
		## the message type recieved and matching response. At least for a basic IP request/handshake.
		if request['dhcp_options']['option 53']['bytes'][-1] == 1: # DHCP Discover
			print(f'[-] Sending: {{"type" : "OFFER", "to" : "{mac}", "offering" : "{self.lease_db.leases_by_mac[mac]}"}}')
			packet += dhcp_fields.TYPE('OFFER')
		if request['dhcp_options']['option 53']['bytes'][-1] == 3: # DHCP Request
			print(f'[-] Sending: {{"type" : "PROVIDED", "to" : "{mac}", "offering" : "{self.lease_db.leases_by_mac[mac]}"}}')
			packet += dhcp_fields.TYPE('ACK')
		
		# Slap on the clients trasnacation identifier so it knows
		# we responded to the request and not some other request it made.	
		packet += dhcp_fields.identifier(self.bind_to)
		
		# We don't honor these, so we're generous with them:
		packet += dhcp_fields.lease_time(43200)
		packet += dhcp_fields.renewal_time(21600)
		packet += dhcp_fields.rebind_time(37800)

		# And the IP, subnet, router(gateway) and DNS information.
		packet += dhcp_fields.subnet(self.subnet.netmask)
		packet += dhcp_fields.broadcast_addr(self.subnet.broadcast_address)
		packet += dhcp_fields.router(self.gateway)
		packet += dhcp_fields.dns_servers(*self.dns_servers)

		# If we have a PXE binary to deliver, add the appropriate options to the request:
		if self.pxe_bin:
			packet += dhcp_fields.tftp_server_name(self.gateway)
			packet += dhcp_fields.boot_file(self.pxe_bin)
			packet += dhcp_fields.boot_file_prefix(self.pxe_dir)
			packet += dhcp_fields.boot_file_configuration(self.pxe_config)

		packet += b'\xff'   #End Option

		"""
		return DHCPResponse(request_frame=frame, data=packet)

class DHCPServer:
	def __init__(self, configuration, leases):
		self.configuration = configuration
		self.leases = leases

		if self.configuration.provision_self:
			for ip in self.ip:
				self.leases.IP.lease(ip, self.mac)
				self.leases.MAC.lease(self.mac, ip)

		self.initiate()

	@property
	def mac(self):
		with open(f'/sys/class/net/{self.configuration.interface}/address', 'r') as fh:
			return fh.read().strip()

	@property
	def ip(self):
		for ip, network in get_network_interfaces().get(self.configuration.interface).items():
			yield ip

	def initiate(self):
		# https://stackoverflow.com/questions/1117958/how-do-i-use-raw-socket-in-python
		# https://stackoverflow.com/a/27823680/929999
		self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
		# https://elixir.bootlin.com/linux/v4.3/source/include/uapi/linux/if_packet.h#L25
		# https://man7.org/linux/man-pages/man7/packet.7.html#Address_types
		# self.socket.bind((self.configuration.interface, socket.ntohs(ETH_P_ALL), 0))#, hatype, haddr))
		self.socket.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
		self.promisciousMode = promisc(self.socket, bytes(self.configuration.interface, 'UTF-8'))
		self.promisciousMode.on()

		self.main_so_id = self.socket.fileno()

		self.pollobj = epoll()
		self.pollobj.register(self.main_so_id, EPOLLIN)

	def close(self):
		self.promisciousMode.off()
		self.pollobj.unregister(self.main_so_id)
		self.socket.close()

	def is_alive(self):
		return True

	def poll(self, timeout=0.001, fileno=None):
		d = dict(self.pollobj.poll(timeout))
		if fileno: return d[fileno] if fileno in d else None
		return d

	def get_frame(self):
		if self.poll():
			data, auxillary_data_raw, flags, addr = self.socket.recvmsg(65535, socket.CMSG_LEN(4096))

			auxillary_items = []
			for message_level, message_type, message_data in auxillary_data_raw:
				if message_level == SOL_PACKET and message_type == PACKET_AUXDATA:
					auxdata = tpacket_auxdata.from_buffer_copy(message_data)
					auxillary_items.append(
						AuxillaryItem(**{
							'status' : auxdata.tp_status,
							'length' : auxdata.tp_len,
							'snap_length' : auxdata.tp_snaplen,
							'mac' : auxdata.tp_mac,
							'net' : auxdata.tp_net,
							'vlan' : auxdata.tp_vlan_tci,
							'padding' : auxdata.tp_padding
						})
					)

			try:
				return Frame(server=self, request=data, auxillary_data=auxillary_items, auxillary_data_raw=auxillary_data_raw, flags=flags, addr=addr)
			except (NonDHCPFrame, NonIPv4Frame, NonBroadcastFrame, InvalidFrameLength):
				# Promiscious socket simply picked up another frame
				pass
			#except pydantic.error_wrappers.ValidationError:
			#	pass
			#except Exception as error:
			#	print(f"Invalid DHCP Frame: {error}\nOn data: {data}")

	def respond(self, response :FrameResponse):
		# If the 'giaddr' field in a DHCP message from a client is non-zero,
		# the server sends any return messages to the 'DHCP server' port on the
		# BOOTP relay agent whose address appears in 'giaddr'. If the 'giaddr'
		# field is zero and the 'ciaddr' field is nonzero, then the server
		# unicasts DHCPOFFER and DHCPACK messages to the address in 'ciaddr'.
		# If 'giaddr' is zero and 'ciaddr' is zero, and the broadcast bit is
		# set, then the server broadcasts DHCPOFFER and DHCPACK messages to
		# 0xffffffff. If the broadcast bit is not set and 'giaddr' is zero and
		# 'ciaddr' is zero, then the server unicasts DHCPOFFER and DHCPACK
		# messages to the client's hardware address and 'yiaddr' address.  In
		# all cases, when 'giaddr' is zero, the server broadcasts any DHCPNAK
		# messages to 0xffffffff.
		
		# if self.bind_to == '255.255.255.255':

		#if response.frame.request_frame.auxillary_data[0].vlan:
		log(f"Broadcasting DHCP response on vlan {response.frame.request_frame.auxillary_data[0].vlan}:", [response.frame.data], response.frame.request_frame.auxillary_data_raw, response.frame.request_frame.flags, (response.frame.request_frame.server.configuration.interface, 68), fg="green", level=logging.INFO)
		self.socket.sendmsg([response.frame.data], response.frame.request_frame.auxillary_data_raw, response.frame.request_frame.flags, (response.frame.request_frame.server.configuration.interface, 68))
		#else:
		#	log(f"[-] Broadcasting back response:", response.frame.data)
		#	self.socket.sendmsg([response.frame.data], response.frame.request_frame.auxillary_data_raw, response.frame.request_frame.flags, ('enp3s0', 68))
		#	#self.socket.sendto(response.frame.data, ('enp3s0', 68))
		# else:
		# 	print(f"[-] Sending directly to {addr}")
		# 	self.socket.sendmsg([packet], auxillary_data_raw, flags, addr)

		# if self.cache_db:
		# 	self.lease_db.save(self.cache_dir + '/' + self.cache_db)
		# 	#save_local_storage(self.cache_dir + '/' + self.cache_db, self.lease_db)

class IPLeases(pydantic.BaseModel):
	__root__: Dict[str, str]

	def __contains__(self, key):
		if type(key) == bytes:
			key = key.decode('utf-8')
		if type(key) == str:
			key = ipaddress.IPv4Address(key)
		return key in self.__root__

	def __getitem__(self, item):
		if type(item) == bytes:
			item = item.decode('utf-8')
		if type(item) == str:
			item = ipaddress.IPv4Address(item)

		return self.__root__[item]

	def lease(self, ip, mac):
		self.__root__[ip] = mac

class MACLeases(pydantic.BaseModel):
	__root__: Dict[str, str]

	def __contains__(self, key):
		return key in self.__root__

	def __getitem__(self, item):  # if you want to use '[]'
		return self.__root__[item]

	def lease(self, mac, ip):
		self.__root__[mac] = ip

class Leases(pydantic.BaseModel):
	IP: IPLeases
	MAC: MACLeases

class Filters(pydantic.BaseModel):
	# https://github.com/samuelcolvin/pydantic/issues/1802
	__root__: Dict[str, Union[str, bool]]

	class Config:
		smart_union = True

class PXEConfiguration(pydantic.BaseModel):
	binary: pathlib.Path
	next_server: ipaddress.IPv4Network
	directory: pathlib.Path = pathlib.Path('/srv/pxe/')

class DHCPSpecifics(pydantic.BaseModel):
	subnet: ipaddress.IPv4Network
	gateway: Optional[ipaddress.IPv4Address] = None
	pxe: Optional[PXEConfiguration] = None
	dns_servers: Optional[List[ipaddress.IPv4Address]] = None

class Configuration(pydantic.BaseModel):
	interface: str
	dhcp: DHCPSpecifics
	provision_self: Optional[bool] = False
	filters: Optional[Filters] = None
	leases: pathlib.Path = pathlib.Path('./leases.json')


if __name__ == '__main__':
	instance = None
	leases = {'IP': {}, 'MAC' : {}}
	Frame.update_forward_refs()

	def sig_handler(signal, frame):
		if instance:
			instance.close()
		exit(0)
	signal.signal(signal.SIGINT, sig_handler)

	parser = argparse.ArgumentParser()
	# Either load options via config
	parser.add_argument("--config", nargs="?", help="JSON configuration file or URL", type=pathlib.Path)
	# and/or override with arguments
	parser.add_argument("--interface", nargs="?", help="Interface to bind to.", type=str)
	parser.add_argument("--leases", nargs="?", help="Path to the JSON lease database", type=pathlib.Path, default=pathlib.Path('/srv/dhcp/leases.db').resolve())
	parser.add_argument("--subnet", nargs="?", help="Subnet with CIDR notation, example 192.168.0.0/24", type=ipaddress.IPv4Network)
	parser.add_argument("--gateway", nargs="?", help="IPv4 address to the default gateway", type=ipaddress.IPv4Address)
	parser.add_argument("--dns-servers", nargs="?", help="comma separated list of DNS servers", type=str)
	parser.add_argument("--pxe-server", nargs="?", help="The next server that facilitates the PXE binaries", type=ipaddress.IPv4Address)
	parser.add_argument("--pxe-binary", nargs="?", help="The binary to tell the client to load", type=pathlib.Path)
	parser.add_argument("--pxe-directory", nargs="?", help="The root of the exposed PXE directory", type=pathlib.Path)
	parser.add_argument("--filters", nargs="?", help="A JSON structure of filters, example: '{\"de:ad:be:ef:00:01\" : true, \"de:ad:be:ef:00:02\" : \"192.168.1.10\"}'\nYou cannot mix True or False, True will only let through the items in the list and block by default. False will let everything through by default but block the specified hosts.", type=str)
	parser.add_argument("--valid-relays", nargs="?", help="A comma separated list of valid relay servers (if found in frames)", type=str)
	parser.add_argument("--provision-self", action='store_true', help="A comma separated list of valid relay servers (if found in frames)", default=False)

	config = {}
	args, unknowns = parser.parse_known_args()
	# preprocess the json files.
	# TODO Expand the url access to the other JSON file arguments ?
	if args.config is not None:
		try:
			# First, let's check if this is a URL scheme instead of a filename
			parsed_url = urllib.parse.urlparse(args.config)

			if not parsed_url.scheme:
				with args.config.resolve().open('r') as fh:
					config = json.load(fh)
			else:
				with urllib.request.urlopen(urllib.request.Request(args.config, headers={'User-Agent': 'ArchInstall'})) as response:
					config = json.loads(response.read())
		except Exception as e:
			raise ValueError(f"Could not load --config because: {e}")

	if args.interface:
		config['interface'] = args.interface
	if args.leases:
		config['leases'] = args.leases
	if args.subnet:
		config['subnet'] = args.subnet
	if args.gateway:
		config['gateway'] = args.gateway
	if args.dns_servers:
		config['dns_servers'] = args.dns_servers
	if args.pxe_server:
		config['pxe_server'] = args.pxe_server
	if args.pxe_binary:
		config['pxe_binary'] = args.pxe_binary
	if args.pxe_directory:
		config['pxe_directory'] = args.pxe_directory
	if args.filters:
		config['filters'] = args.filters
	if args.valid_relays:
		config['valid_relays'] = args.valid_relays
	if args.provision_self:
		config['provision_self'] = args.provision_self

	if not config.get('interface'):
		raise ValueError(f"Need to supply --interface (or 'interface' via --config)")

	config['dhcp'] = {'subnet' : config.get('subnet')}
	if config.get('gateway'):
		config['dhcp']['gateway'] = config['gateway']
	if config.get('pxe'):
		config['dhcp']['pxe'] = config['pxe'] #TODO: Convert into a dict struct for parsing
	if config.get('dns_servers'):
		config['dhcp']['dns_servers'] = config['dns_servers'].split(',')

	if not config['dhcp']['subnet']:
		# Attempt to autodetect the network + netmask for the given --interface
		# and use that as our --subnet if none was given.
		for ip, network in get_network_interfaces().get(config['interface']).items():
			config['dhcp']['subnet'] = network
			break

	if args.filters:
		config['filters'] = Filters.parse_obj(json.loads(args.filters))

	config = Configuration(**config)

	if (iface_ip := get_ip_address(config.interface)) and iface_ip in config.dhcp.subnet:
		# If our interface has an IP in the DHCP subnet range,
		# that means we should avoid giving it out and provision it
		# to ourselves to avoid conflicts.
		# (The actual provisioning happens later)
		config.provision_self = True

	if config.provision_self and iface_ip is None:
		raise ValueError(f"You've indicated that we have an IP on the interface with --provision-self but no IP found on {config.interface}")

	if config.leases and config.leases.resolve().exists():
		with config.leases.resolve().open('r') as fh:
			leases = Leases(json.loads(fh.read()))

	instance = DHCPServer(config, Leases(**leases))
	while instance.is_alive():
		if frame := instance.get_frame():
			instance.respond(frame.response())

	"""
	if args['multi_bind']:
		instances.append(dhcp_serve(lease_db=lease_database, bind_to=get_ip_address(args['interface']), **{**args, 'gateway' : get_ip_address(args['interface'])}))
	instances.append(dhcp_serve(lease_db=lease_database, bind_to='255.255.255.255', **args))

	while 1:
		for instance in instances:
			if instance.poll():
				instance.parse()
	"""