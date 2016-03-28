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

def binInt(num):
	## TODO: Discard, probably not doing what i initially thought it did (results are similar, up to a certain number)
	##   binInt(53), hexInt(53)  vs  binInt(255), hexInt(255) : <
	""" Converts a int() to bytes() object with proper \x00 declaration (and not a hex(num) representation) """
	return bytes(chr(num), 'UTF-8')

def hexInt(num):
	""" Converts a int() to hex() representation in bytes() format. """
	return bytearray.fromhex(hex(num)[2:].zfill(2))

def int_array_to_hex(ia):
	""" takes a list() of int() types and convert them to a bytes() string with proper hex(\x00) declaration """
	b = b''
	for i in ia:
		b += hexInt(i)
	return b

def b_fill(byte, l):
	""" Pads a bytes() string with \x00 """
	return b''.join([b'\x00'*(l-len(byte)), byte])