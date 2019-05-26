#!/usr/bin/env python

'''A Pure Python ASN.1 encoder/decoder w/ a calling interface in the spirit
of pickle.

The default dumps/loads uses a profile of ASN.1 that supports serialization
of key/value pairs.  This is non-standard.  Instantiate the class ASN1Coder
to get a pure ASN.1 serializer/deserializer.

All lengths must be specified.  That is that End-of-contents octets
MUST NOT be used.  The shorted form of length encoding MUST be used.
A longer length encoding MUST be rejected.'''

__author__ = 'John-Mark Gurney'
__copyright__ = 'Copyright 2016 John-Mark Gurney.  All rights reserved.'
__license__ = '2-clause BSD license'

# Copyright 2016, John-Mark Gurney
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies,
# either expressed or implied, of the Project.

import datetime
import math
import os
import sys
import unittest

__all__ = [ 'dumps', 'loads', 'ASN1Coder' ]

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

class ASN1Coder(object):
	'''A class that contains an PASN.1 encoder/decoder.

	Exports two methods, loads and dumps.'''

	def __init__(self, coerce=None):
		'''If the arg coerce is provided, when dumping the object,
		if the type is not found, the coerce function will be called
		with the obj.  It is expected to return a tuple of a string
		and an object that has the method w/ the string as defined:
			'bool': __nonzero__
			'float': compatible w/ float
			'int': compatible w/ int
			'list': __iter__
			'set': __iter__
			'bytes': __str__
			'null': no method needed
			'unicode': encode method returns UTF-8 encoded bytes
			'datetime': strftime and microsecond
		'''

		self.coerce = coerce

	_typemap = {
		bool: 'bool',
		float: 'float',
		int: 'int',
		list: 'list',
		long: 'int',
		set: 'set',
		str: 'bytes',
		type(None): 'null',
		unicode: 'unicode',
		#decimal.Decimal: 'float',
		datetime.datetime: 'datetime',
		#datetime.timedelta: 'timedelta',
	}
	_tagmap = {
		'\x01':	'bool',
		'\x02':	'int',
		'\x04':	'bytes',
		'\x05':	'null',
		'\x09':	'float',
		'\x0c':	'unicode',
		'\x18': 'datetime',
		'\x30':	'list',
		'\x31': 'set',
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

	def enc_list(self, obj):
		r = ''.join(self.dumps(x) for x in obj)
		return _encodelen(len(r)) + r

	def dec_list(self, d, pos, end):
		r = []
		vend = pos
		while pos < end:
			v, vend = self._loads(d, pos, end)
			if vend > end:
				raise ValueError('load past end')
			r.append(v)
			pos = vend

		return r, vend

	enc_set = enc_list

	def dec_set(self, d, pos, end):
		r, end = self.dec_list(d, pos, end)
		return set(r), end

	@staticmethod
	def enc_bytes(obj):
		return _encodelen(len(obj)) + bytes(obj)

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
		el = (e.bit_length() + 7 + 1) // 8  # + 1 is sign bit
		if el > 2:
			raise ValueError('exponent too large')

		if e < 0:
			e += 256**el	# convert negative to twos-complement

		v = el - 1
		encexp = _numtostr(e)

		val |= v
		r = chr(val) + encexp + _numtostr(m)
		return _encodelen(len(r)) + r

	def dec_float(self, d, pos, end):
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
		elif v & 0b110000:
			raise ValueError('base must be 2')
		elif v & 0b1100:
			raise ValueError('scaling factor must be 0')
		elif v & 0b11000000 == 0:
			raise ValueError('decimal encoding not supported')
		#elif v & 0b11000000 == 0b01000000:
		#	raise ValueError('invalid encoding')

		if (v & 3) >= 2:
			raise ValueError('large exponents not supported')
		pexp = pos + 1
		eexp = pos + 1 + (v & 3) + 1

		exp = self.dec_int(d, pexp, eexp)[0]

		n = float(int(d[eexp:end].encode('hex'), 16))
		r = n * 2 ** exp
		if v & 0b1000000:
			r = -r

		return r, end

	def dumps(self, obj):
		'''Convert obj into an array of bytes.'''

		try:
			tf = self._typemap[type(obj)]
		except KeyError:
			if self.coerce is None:
				raise TypeError('unhandled object: %s' % `obj`)

			tf, obj = self.coerce(obj)

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

	def enc_datetime(self, obj):
		ts = obj.strftime('%Y%m%d%H%M%S')
		if obj.microsecond:
			ts += ('.%06d' % obj.microsecond).rstrip('0')
		ts += 'Z'
		return _encodelen(len(ts)) + ts

	def dec_datetime(self, data, pos, end):
		ts = data[pos:end]
		if ts[-1] != 'Z':
			raise ValueError('last character must be Z')

		# Real bug is in strptime, but work around it here.
		if ' ' in data:
			raise ValueError('no spaces are allowed')

		if '.' in ts:
			fstr = '%Y%m%d%H%M%S.%fZ'
			if ts.endswith('0Z'):
				raise ValueError('invalid trailing zeros')
		else:
			fstr = '%Y%m%d%H%M%SZ'
		return datetime.datetime.strptime(ts, fstr), end

	def loads(self, data, pos=0, end=None, consume=False):
		'''Load from data, starting at pos (optional), and ending
		at end (optional).  If it is required to consume the
		whole string (not the default), set consume to True, and
		a ValueError will be raised if the string is not
		completely consumed.  The second item in ValueError will
		be the possition that was the detected end.'''

		if end is None:
			end = len(data)
		r, e = self._loads(data, pos, end)

		if consume and e != end:
			raise ValueError('entire string not consumed', e)

		return r

class ASN1DictCoder(ASN1Coder):
	'''This adds support for the non-standard dict serialization.

	The coerce method also supports the following type:
			'dict': iteritems
	'''

	_typemap = ASN1Coder._typemap.copy()
	_typemap[dict] = 'dict'
	_tagmap = ASN1Coder._tagmap.copy()
	_tagmap['\xe0'] = 'dict'
	_typetag = dict((v, k) for k, v in _tagmap.iteritems())

	def enc_dict(self, obj):
		#it = list(obj.iteritems())
		#it.sort()
		r = ''.join(self.dumps(k) + self.dumps(v) for k, v in
		    obj.iteritems())
		return _encodelen(len(r)) + r

	def dec_dict(self, d, pos, end):
		r = {}
		vend = pos
		while pos < end:
			k, kend = self._loads(d, pos, end)
			#if kend > end:
			#	raise ValueError('key past end')
			v, vend = self._loads(d, kend, end)
			if vend > end:
				raise ValueError('value past end')

			r[k] = v
			pos = vend

		return r, vend

_coder = ASN1DictCoder()
dumps = _coder.dumps
loads = _coder.loads

def deeptypecmp(obj, o):
	#print 'dtc:', `obj`, `o`
	if type(obj) != type(o):
		return False
	if type(obj) in (str, unicode):
		return True

	if type(obj) in (list, set):
		for i, j in zip(obj, o):
			if not deeptypecmp(i, j):
				return False

	if type(obj) in (dict,):
		itms = obj.items()
		itms.sort()
		nitms = o.items()
		nitms.sort()
		for (k, v), (nk, nv) in zip(itms, nitms):
			if not deeptypecmp(k, nk):
				return False
			if not deeptypecmp(v, nv):
				return False
			
	return True

class Test_deeptypecmp(unittest.TestCase):
	def test_true(self):
		for i in ((1,1), ('sldkfj', 'sldkfj')
		    ):
			self.assertTrue(deeptypecmp(*i))

	def test_false(self):
		for i in (([[]], [{}]), ([1], ['str']), ([], set()),
		    ({1: 2, 5: u'sdlkfj'}, {1: 2, 5: 'sdlkfj'}),
		    ({1: 2, u'sdlkfj': 5}, {1: 2, 'sdlkfj': 5}),
		    ):
			self.assertFalse(deeptypecmp(*i))

def genfailures(obj):
	s = dumps(obj)
	for i in xrange(len(s)):
		for j in (chr(x) for x in xrange(256)):
			ts = s[:i] + j + s[i + 1:]
			if ts == s:
				continue
			try:
				o = loads(ts, consume=True)
				if o != obj or not deeptypecmp(o, obj):
					raise ValueError
			except (ValueError, KeyError, IndexError, TypeError):
				pass
			else:	# pragma: no cover
				raise AssertionError('uncaught modification: %s, byte %d, orig: %02x' % (ts.encode('hex'), i, ord(s[i])))

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

		self.assertEqual(dumps(.15625), '090380fb05'.decode('hex'))

	def test_fuzzing(self):
		# Make sure that when a failure is detected here, that it
		# gets added to test_invalids, so that this function may be
		# disabled.
		genfailures(float(1))
		genfailures([ 1, 2, 'sdlkfj' ])
		genfailures({ 1: 2, 5: 'sdlkfj' })
		genfailures(set([ 1, 2, 'sdlkfj' ]))
		genfailures(True)
		genfailures(datetime.datetime.utcnow())

	def test_invalids(self):
		# Add tests for base 8, 16 floats among others
		for v in [ '010101',
		    '0903040001',	# float scaling factor
		    '0903840001',	# float scaling factor
		    '0903100001',	# float base
		    '0903900001',	# float base
		    '0903000001',	# float decimal encoding
		    '0903830001',	# float exponent encoding
		    '090b827fffcc0df505d0fa58f7', # float large exponent
		    '3007020101020102040673646c6b666a',	# list short string still valid
		    'e007020101020102020105040673646c6b666a', # dict short value still valid
		    '181632303136303231353038343031362e3539303839305a', #datetime w/ trailing zero
		    '181632303136303231373136343034372e3035343433367a', #datetime w/ lower z
		    '181632303136313220383031303933302e3931353133385a', #datetime w/ space
		    ]:
			self.assertRaises(ValueError, loads, v.decode('hex'))

	def test_invalid_floats(self):
		import mock
		with mock.patch('math.frexp', return_value=(.87232, 1 << 23)):
			self.assertRaises(ValueError, dumps, 1.1)

	def test_consume(self):
		b = dumps(5)
		self.assertRaises(ValueError, loads, b + '398473',
		    consume=True)

		# XXX - still possible that an internal data member
		# doesn't consume all

	# XXX - test that sets are ordered properly
	# XXX - test that dicts are ordered properly..

	def test_nan(self):
		s = dumps(float('nan'))
		v = loads(s)
		self.assertTrue(math.isnan(v))

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

	def test_invaliddate(self):
		pass
		# XXX - add test to reject datetime w/ tzinfo, or that it
		# handles it properly

	def test_dumps(self):
		for i in [ None,
		    True, False,
		    -1, 0, 1, 255, 256, -255, -256,
		    23498732498723, -2398729387234,
		    (1<<2383) + 23984734, (-1<<1983) + 23984723984,
		    float(0), float('-0'), float('inf'), float('-inf'),
		    float(1.0), float(-1.0), float('353.3487'),
		    float('2.38723873e+307'), float('2.387349e-317'),
		    sys.float_info.max, sys.float_info.min,
		    float('.15625'),
		    'weoifjwef',
		    u'\U0001f4a9',
		    [], [ 1,2,3 ],
		    {}, { 5: 10, 'adfkj': 34 },
		    set(), set((1,2,3)),
		    set((1,'sjlfdkj', None, float('inf'))),
		    datetime.datetime.utcnow(),
		    datetime.datetime.utcnow().replace(microsecond=0),
		    datetime.datetime.utcnow().replace(microsecond=1000),
		    ]:
			s = dumps(i)
			o = loads(s)
			self.assertEqual(i, o)

		tobj = { 1: 'dflkj', 5: u'sdlkfj', 'float': 1,
		    'largeint': 1<<342, 'list': [ 1, 2, u'str', 'str' ] }

		out = dumps(tobj)
		self.assertEqual(tobj, loads(out))

	def test_coerce(self):
		class Foo:
			pass

		class Bar:
			pass

		class Baz:
			pass
		def coerce(obj):
			if isinstance(obj, Foo):
				return 'list', obj.lst
			elif isinstance(obj, Baz):
				return 'bytes', obj.s

			raise TypeError('unknown type')

		ac = ASN1Coder(coerce)

		v = [1, 2, 3]
		o = Foo()
		o.lst = v

		self.assertEqual(ac.loads(ac.dumps(o)), v)
		self.assertRaises(TypeError, ac.dumps, Bar())

		v = u'oiejfd'
		o = Baz()
		o.s = v

		es = ac.dumps(o)
		self.assertEqual(ac.loads(es), v)
		self.assertIsInstance(es, bytes)

		self.assertRaises(TypeError, dumps, o)

	def test_loads(self):
		self.assertRaises(ValueError, loads, '\x00\x02\x00')

	def test_nodict(self):
		'''Verify that ASN1Coder does not support dict.'''

		self.assertRaises(KeyError, ASN1Coder().loads, dumps({}))
