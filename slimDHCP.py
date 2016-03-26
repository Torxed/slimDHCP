import struct
from socket import *
from threading import *
from os.path import isfile, abspath, getsize

import sys

class tftp(Thread):
	def __init__(self):
		Thread.__init__(self)
		self.sock = socket(AF_INET, SOCK_DGRAM) # UDP
		self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		self.sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
		self.sock.setsockopt(SOL_SOCKET, 25, b'ens37\0')
		self.sock.bind(('172.16.0.1', 69))
		self.start()

		self.active_file = None
		self.block_size = None

	def run(self):
		main = None
		for t in enumerate():
			if t.name == 'MainThread':
				main = t
				break

		while main and main.isAlive():
			data, addr = self.sock.recvfrom(8192) # buffer size is 1024 bytes
			print(addr, [data])

			msg_type = struct.unpack('>H', data[:2])

			if msg_type[0] == 1: # READ request
				file, data = data[2:].split(b'\x00',1)
				file = file.decode('utf-8')
				print('TFTP:', file)
				if isfile(abspath('./'+file)):
					self.active_file = abspath('./'+file)

					data = data.split(b'\x00')
					conf = {}
					conf[b'tsize'] = bytes(str(getsize(abspath('./'+file))), 'UTF-8')
					if b'blksize' in data:
						conf[b'blksize'] = data[data.index(b'blksize')+1]
					else:
						conf[b'blksize'] = b'1408'
						print('Defaulting blocksize to 1408 because:', data)
					self.block_size = int(conf[b'blksize'])

					resp = b'\x00\x06'
					if b'tsize' in conf:
						resp += b'tsize\x00'+conf[b'tsize']+b'\x00'
					if b'blksize' in conf:
						resp += b'blksize\x00'+conf[b'blksize']+b'\x00'

					print([resp])
					self.sock.sendto(resp, (addr[0], addr[1]))
				else:
					print('** File missing:', abspath('./'+file))
					self.sock.sendto(b'\x00\x05\x00\x01File not found', (addr[0], addr[1]))

			elif msg_type[0] == 4: # ACK on the file
				block = struct.unpack('>H', data[2:4])[0]
				print('Trying to retrieve block', block+1, 'of', self.active_file)
				with open(self.active_file, 'rb') as fh:
					fh.seek(block*self.block_size)
					data = fh.read(self.block_size)
					if len(data) <= 0:
						resp = b'\x00\x03'+struct.pack('>H', block+1)
						self.sock.sendto(resp, (addr[0], addr[1]))
						continue

					resp = b'\x00\x03'+struct.pack('>H', block+1)+data
					self.sock.sendto(resp, (addr[0], addr[1]))

if len(sys.argv) > 2
	tftp()

sock = socket(AF_INET, SOCK_DGRAM) # UDP
sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
sock.setsockopt(SOL_SOCKET, 25, b'ens37\0')
sock.bind(('255.255.255.255', 67))

def byte_to_bin(bs, bin_map=None):
	raw = []
	index = 0
	for length in bin_map:
		#print('Block:',bs[index:index+length], end=' - ')
		#print('Binary:', ['{0:b}'.format(i).zfill(8) for i in bs[index:index+length]])
		
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

def bin_str_to_byte(s):
	b = b''
	for index in range(len(s)):
		b += bytes([int(s[index],2)])
	return b

def binInt(num):
	return bytes(chr(num), 'UTF-8')

def int_array_to_hex(ia):
	b = b''
	for i in ia:
		b += bytearray.fromhex(hex(i)[2:].zfill(2))
	return b

def b_fill(byte, l):
	return b''.join([b'\x00'*(l-len(byte)), byte])

discover = [1, 1, 1, 1, 4, 2, 2, 4, 4, 4, 4, 6, 10, 64, 128, 4, 3]
disc_map = ['msg type',
			'hw type',
			'hw addr len',
			'hops',
			'transaction id',
			'elapsed',
			'bootp flags',
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
	data, addr = sock.recvfrom(8192) # buffer size is 1024 bytes
	binary = list(byte_to_bin(data, bin_map=discover))
	packet = b''

	request = {}
	for index in range(len(binary)):
		request[disc_map[index]] = {'binary' : binary[index], 'hex' : bin_str_to_byte(binary[index])}

	parameters = request['other']['binary']
	parameter_len = ord(bin_str_to_byte([parameters[1]]))

	request['parameters'] = {}
	

	for item in range(parameter_len):
		request['parameters'][item] = {
		'binary' : parameters[item], 'hex' : bin_str_to_byte([parameters[item]])}

	pxe_host = int_array_to_hex([172,16,0,1])
	pxe_file = b'/pxelinux.0'
	if request['msg type']['hex'] == b'\x01': # Message type: Boot request (1)
		packet += b'\x02'   #Message type: DHCP Offer
		packet += b'\x01'   #Hardware type: Ethernet
		packet += b'\x06'   #Hardware address length: 6
		packet += b'\x00'   #Hops: 0
		packet += request['transaction id']['hex']   #Transaction ID
		packet += b'\x00\x00'  #Seconds elapsed: 0
		packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
		packet += b'\x00\x00\x00\x00'   # Client IP address: 0.0.0.0
		packet += int_array_to_hex([172,16,0,100])   # The IP offered to the client
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
		if request['option 53']['hex'][-1] == 1: # DHCP Discover
			packet += binInt(53)+b'\x01\x02'   # DHCP Offer
		if request['option 53']['hex'][-1] == 3: # DHCP Request
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
		packet += binInt(1)+b'\x04'+int_array_to_hex([255,255,255,0]) #Subnet mask
		packet += binInt(3)+b'\x04'+int_array_to_hex([172,16,0,1]) # Router
		packet += binInt(6)+b'\x08'+int_array_to_hex([8,8,8,8])+int_array_to_hex([4,4,4,4]) # Domain name servers

		packet += b'\xff'   #End Option
		packet += b'\x00'*22 # Padding, not sure how much is needed atm but this does it :)

	if len(packet) > 0:
		sock.sendto(packet, ('255.255.255.255', 68))