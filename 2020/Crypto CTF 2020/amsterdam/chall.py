from Crypto.Util.number import *
from functools import reduce
import operator
from secret import flag, n, k

def comb(n, k):
	if k > n :
		return 0
	k = min(k, n - k)
	u = reduce(operator.mul, range(n, n - k, -1), 1)
	d = reduce(operator.mul, range(1, k + 1), 1)
	return u // d

def encrypt(msg, n, k):
	msg = bytes_to_long(msg.encode('utf-8'))
	if msg >= comb(n, k):
		return -1
	m = ['1'] + ['0' for i in range(n - 1)]
	for i in range(1, n + 1):
		if msg >= comb(n - i, k):
			m[i-1]= '1'
			msg -= comb(n - i, k)
			k -= 1
	m = int(''.join(m), 2)
	i, z = 0, [0 for i in range(n - 1)]
	c = 0
	while (m > 0):
		if m % 4 == 1:
			c += 3 ** i
			m -= 1
		elif m % 4 == 3:
			c += 2 * 3 ** i
			m += 1
		m //= 2
		i += 1
	return c

enc = encrypt(flag, n, k)
print('enc =', enc)

# enc = 5550332817876280162274999855997378479609235817133438293571677699650886802393479724923012712512679874728166741238894341948016359931375508700911359897203801700186950730629587624939700035031277025534500760060328480444149259318830785583493