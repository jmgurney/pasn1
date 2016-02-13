#!/usr/bin/env python

# A Pure Python ASN.1 encoder/decoder w/ a calling interface in the spirit
# of pickle.  It will automaticly do the correct thing if possible.
#
# This uses a profile of ASN.1.
#
# All lengths must be specified.  That is that End-of-contents octets
# MUST not be used.  The shorted form of length encoding MUST be used.
# A longer length encoding MUST be rejected.

import math
import os
import pdb
import sys
import unittest

def _numtostr(n):
	hs = '%x' % n
	if len(hs) & 1 == 1:
		hs = '0' + hs
	bs = hs.decode('hex')

	return bs

def _encodelen(l):
	'''Takes l as a length value, and returns a byte string that
	represents l per ASN.1 rules.'''

	if l < 128:
		return chr(l)

	bs = _numtostr(l)
	return chr(len(bs) | 0x80) + bs

def _decodelen(d, pos=0):
	'''Returns the length, and number of bytes required.'''

	odp = ord(d[pos])
	if odp < 128:
		return ord(d[pos]), 1
	else:
		l = odp & 0x7f
		return int(d[pos + 1:pos + 1 + l].encode('hex'), 16), l + 1

class Test_codelen(unittest.TestCase):
	_testdata = [
		(2, '\x02'),
		(127, '\x7f'),
		(128, '\x81\x80'),
		(255, '\x81\xff'),
		(256, '\x82\x01\x00'),
		(65536-1, '\x82\xff\xff'),
		(65536, '\x83\x01\x00\x00'),
	]

	def test_el(self):
		for i, j in self._testdata:
			self.assertEqual(_encodelen(i), j)
			self.assertEqual(_decodelen(j), (i, len(j)))

def _splitfloat(f):
	m, e = math.frexp(f)
	# XXX - less than ideal
	while m != math.trunc(m):
		m *= 2
		e -= 1

	return m, e

class TestSplitFloat(unittest.TestCase):
	def test_sf(self):
		for a, b in [ (0x2421, -32), (0x5382f, 238),
		    (0x1fa8c3b094adf1, 971) ]:
			self.assertEqual(_splitfloat(a * 2**b), (a, b))

class ASN1Object:
	def __init__(self, tag):
		self._tag = tag

class ASN1Coder(object):
	def __init__(self):
		pass

	_typemap = {
		bool: 'bool',
		dict: 'dict',
		float: 'float',
		int: 'int',
		list: 'list',
		long: 'int',
		set: 'set',
		str: 'bytes',
		type(None): 'null',
		unicode: 'unicode',
	}
	_tagmap = {
		'\x01':	'bool',
		'\x02':	'int',
		'\x04':	'bytes',
		'\x05':	'null',
		'\x09':	'float',
		'\x0c':	'unicode',
		'\x30':	'list',
		'\x31': 'set',
		'\xc0':	'dict',
		#'xxx': 'datetime',
	}

	_typetag = dict((v, k) for k, v in _tagmap.iteritems())

	@staticmethod
	def enc_int(obj):
		l = obj.bit_length()
		l += 1	# space for sign bit

		l = (l + 7) // 8

		if obj < 0:
			obj += 1 << (l * 8) # twos-complement conversion

		v = _numtostr(obj)
		if len(v) != l:
			# XXX - is this a problem for signed values?
			v = '\x00' + v # add sign octect

		return _encodelen(l) + v

	@staticmethod
	def dec_int(d, pos, end):
		if pos == end:
			return 0, end

		v = int(d[pos:end].encode('hex'), 16)
		av = 1 << ((end - pos) * 8 - 1) # sign bit
		if v > av:
			v -= av * 2 # twos-complement conversion

		return v, end

	@staticmethod
	def enc_bool(obj):
		return '\x01' + ('\xff' if obj else '\x00')

	def dec_bool(self, d, pos, end):
		v = self.dec_int(d, pos, end)[0]
		if v not in (-1, 0):
			raise ValueError('invalid bool value: %d' % v)

		return bool(v), end

	@staticmethod
	def enc_null(obj):
		return '\x00'

	@staticmethod
	def dec_null(d, pos, end):
		return None, end

	def enc_dict(self, obj):
		#it = list(obj.iteritems())
		#it.sort()
		r = ''.join(self.dumps(k) + self.dumps(v) for k, v in obj.iteritems())
		return _encodelen(len(r)) + r

	def dec_dict(self, d, pos, end):
		r = {}
		while pos < end:
			k, kend = self._loads(d, pos, end)
			v, vend = self._loads(d, kend, end)

			r[k] = v
			pos = vend

		return r, vend

	def enc_set(self, obj):
		r = ''.join(self.dumps(x) for x in obj)
		return _encodelen(len(r)) + r

	def dec_set(self, d, pos, end):
		r, end = self.dec_list(d, pos, end)
		return set(r), end

	def enc_list(self, obj):
		r = ''.join(self.dumps(x) for x in obj)
		return _encodelen(len(r)) + r

	def dec_list(self, d, pos, end):
		r = []
		while pos < end:
			v, vend = self._loads(d, pos, end)
			r.append(v)
			pos = vend

		return r, vend

	@staticmethod
	def enc_bytes(obj):
		return _encodelen(len(obj)) + obj

	@staticmethod
	def dec_bytes(d, pos, end):
		return d[pos:end], end

	@staticmethod
	def enc_unicode(obj):
		encobj = obj.encode('utf-8')
		return _encodelen(len(encobj)) + encobj

	def dec_unicode(self, d, pos, end):
		return d[pos:end].decode('utf-8'), end

	@staticmethod
	def enc_float(obj):
		s = math.copysign(1, obj)
		if math.isnan(obj):
			return _encodelen(1) + chr(0b01000010)
		elif math.isinf(obj):
			if s == 1:
				return _encodelen(1) + chr(0b01000000)
			else:
				return _encodelen(1) + chr(0b01000001)
		elif obj == 0:
			if s == 1:
				return _encodelen(0)
			else:
				return _encodelen(1) + chr(0b01000011)

		m, e = _splitfloat(obj)

		# Binary encoding
		val = 0x80
		if m < 0:
			val |= 0x40
			m = -m
		# Base 2
		# XXX - negative e
		el = (e.bit_length() + 7) // 8
		if el > 3:
			v = 0x3
			encexp = _encodelen(el) + _numtostr(e)
		else:
			v = el - 1
			encexp = _numtostr(e)

		return chr(val) + encexp + _numtostr(m)

	@staticmethod
	def dec_float(d, pos, end):
		if pos == end:
			return float(0), end

		v = ord(d[pos])
		if v == 0b01000000:
			return float('inf'), end
		elif v == 0b01000001:
			return float('-inf'), end
		elif v == 0b01000010:
			return float('nan'), end
		elif v == 0b01000011:
			return float('-0'), end
		#elif v & 0b11000000 == 0b01000000:
		#	raise ValueError('invalid encoding')

		raise NotImplementedError

	def dumps(self, obj):
		tf = self._typemap[type(obj)]
		fun = getattr(self, 'enc_%s' % tf)
		return self._typetag[tf] + fun(obj)

	def _loads(self, data, pos, end):
		tag = data[pos]
		l, b = _decodelen(data, pos + 1)
		if len(data) < pos + 1 + b + l:
			raise ValueError('string not long enough')

		# XXX - enforce that len(data) == end?
		end = pos + 1 + b + l

		t = self._tagmap[tag]
		fun = getattr(self, 'dec_%s' % t)
		return fun(data, pos + 1 + b, end)

	def loads(self, data, pos=0, end=None, consume=False):
		if end is None:
			end = len(data)
		r, e = self._loads(data, pos, end)

		if consume and e != end:
			raise ValueError('entire string not consumed')
		return r

_coder = ASN1Coder()
dumps = _coder.dumps
loads = _coder.loads

class TestCode(unittest.TestCase):
	def test_primv(self):
		self.assertEqual(dumps(-257), '0202feff'.decode('hex'))
		self.assertEqual(dumps(-256), '0202ff00'.decode('hex'))
		self.assertEqual(dumps(-255), '0202ff01'.decode('hex'))
		self.assertEqual(dumps(-1), '0201ff'.decode('hex'))
		self.assertEqual(dumps(5), '020105'.decode('hex'))
		self.assertEqual(dumps(128), '02020080'.decode('hex'))
		self.assertEqual(dumps(256), '02020100'.decode('hex'))

		self.assertEqual(dumps(False), '010100'.decode('hex'))
		self.assertEqual(dumps(True), '0101ff'.decode('hex'))

		self.assertEqual(dumps(None), '0500'.decode('hex'))

	def test_consume(self):
		b = dumps(5)
		self.assertRaises(ValueError, loads, b + '398473', consume=True)

		# XXX - still possible that an internal data member
		# doesn't consume all

	def test_nan(self):
		s = dumps(float('nan'))
		v = loads(s)
		self.assertTrue(math.isnan(v))

	def test_invalids(self):
		for v in [ '010101', ]:
			self.assertRaises(ValueError, loads, v.decode('hex'))

	def test_cryptoutilasn1(self):
		'''Test DER sequences generated by Crypto.Util.asn1.'''

		for s, v in [ ('\x02\x03$\x8a\xf9', 2394873),
		    ('\x05\x00', None),
		    ('\x02\x03\x00\x96I', 38473),
		    ('\x04\x81\xc8' + '\x00' * 200, '\x00' * 200),
		    ]:
			self.assertEqual(loads(s), v)

	def test_longstrings(self):
		for i in (203, 65484):
			s = os.urandom(i)
			v = dumps(s)
			self.assertEqual(loads(v), s)

	def test_dumps(self):
		for i in [ None,
		    True, False,
		    -1, 0, 1, 255, 256, -255, -256, 23498732498723, -2398729387234, (1<<2383) + 23984734, (-1<<1983) + 23984723984,
		    float(0), float('-0'), float('inf'), float('-inf'),
		    'weoifjwef',
		    u'\U0001f4a9',
		    set((1,2,3)), set((1,'sjlfdkj', None, float('inf'))),
		    ]:
			s = dumps(i)
			o = loads(s)
			self.assertEqual(i, o)

		tobj = { 1: 'dflkj', 5: u'sdlkfj', 'float': 1, 'largeint': 1<<342, 'list': [ 1, 2, u'str', 'str' ] }

		out = dumps(tobj)
		self.assertEqual(tobj, loads(out))

	def test_loads(self):
		self.assertRaises(ValueError, loads, '\x00\x02\x00')

if __name__ == '__main__':
	pass
