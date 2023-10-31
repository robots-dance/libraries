#!/usr/bin/python2.7
from bigfloat import *
import math
import sys

class ErrorCode:
	USAGE_ERR = 1
	BAD_WHAT = 2
	BAD_DIGEST_SIZE = 3
	NO_IMPL = 4
	NO_SUPPORTED_SIZE = 5

def GetPrimes( minVal, maxVal ):
	if minVal > maxVal or minVal < 2 or maxVal < 2:
		return None
	result = []
	for curNum in xrange( minVal, maxVal + 1 ):
		divisorsCount = 0
		for divisor in xrange( 2, curNum ): 
			if ( curNum % divisor ) == 0:
				divisorsCount += 1
		if divisorsCount == 0:
			result.append( curNum )
	return result

# ==== Entry Point ====
argsCount = len( sys.argv )
if argsCount < 3:
	print "Usage: ./calc-roots.py <what> <digest-size>"
	sys.exit( ErrorCode.USAGE_ERR )

what = sys.argv[ 1 ]
digestSizeStr = sys.argv[ 2 ]
short512Used = False
clippedSize = 0
try:
	digestSize = int( digestSizeStr )
except ValueError:
	error = True
	slashIndex = digestSizeStr.find( "/" )
	if slashIndex != -1:
		leftPart = digestSizeStr[ : slashIndex ]	
		rightPart = digestSizeStr[ slashIndex + 1 : ]
		try:
			leftSize = int( leftPart )
			rightSize = int( rightPart )
			if leftSize != 512:
				raise ValueError()
			if rightSize >= leftSize or rightSize <= 0:
				raise ValueError()
			if rightSize == 384:
				raise ValueError()
			digestSize = 512
			clippedSize = rightSize
			error = False
			short512Used = True
		except ValueError:
			pass
	if error:
		print "incorrect digest size"
		sys.exit( ErrorCode.BAD_DIGEST_SIZE )

if what == "init":
	if digestSize == 224:
		for prime in GetPrimes( 23, 53 ):
			with quadruple_precision:
				sqrtValue = sqrt( prime )
				fractValue = frac( sqrtValue )
				result = int( fractValue * 2 ** 64 )
				result = result & 0x00000000FFFFFFFF
				print "%x" % result
	
	elif digestSize == 256:
		for prime in  GetPrimes( 2, 19 ):
			with double_precision:
				sqrtValue = sqrt( prime )
				fractValue = frac( sqrtValue )
				print "%x" % int( fractValue * 2 ** 32 )
	
	elif digestSize == 384 or digestSize == 512:
		if digestSize == 384:
			minVal, maxVal = 23, 53
		else:
			minVal, maxVal = 2, 19
		values = []
		for prime in GetPrimes( minVal, maxVal ):
			with quadruple_precision:
				sqrtValue = sqrt( prime )
				fractValue = frac( sqrtValue )
				values.append( int( fractValue * 2 ** 64 ) )
		if short512Used:
			valIndex = 0
			for valIndex in xrange( len( values ) ):
				values[ valIndex ] ^= 0xA5A5A5A5A5A5A5A5
			print "no implemented"
			sys.exit( ErrorCode.NO_IMPL )
		for val in values:
			print "%x" % val
	
	else:
		print "no supported diggest size"
		sys.exit( ErrorCode.NO_SUPPORTED_SIZE )

elif what == "k":
	if digestSize == 160:
		for num in ( 2, 3, 5, 10 ):
			print "%x" % ( math.sqrt( num ) / 4 * 2 ** 32 )
	elif digestSize == 224 or digestSize == 256:
		for prime in GetPrimes( 2, 311 ):
			with double_precision:
				cbrtValue = cbrt( prime )
				fractValue = frac( cbrtValue )
				print "%x" % int( fractValue * 2 ** 32 )
	elif digestSize == 384 or digestSize == 512:
		for prime in GetPrimes( 2, 409 ):
			with quadruple_precision:
				cbrtValue = cbrt( prime )
				fractValue = frac( cbrtValue )
				print "%x" % int( fractValue * 2 ** 64 )
else:
	print "unknown what value"
	sys.exit( ErrorCode.BAD_WHAT )
