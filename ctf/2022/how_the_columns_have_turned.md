# Challenge: How The Columns Have Turned

## Category: CRYPTO

This challenge is a part of the _'Cyber Apocalypse 2022'_ . I solved it for the team i played with 'ARESTeamITA' and in my opinion is a quite good challenge to explain a
fundamental part of Block Ciphers: column operation.

Real world block cipher are build upon few simple concepts repetead every iteration, how the columns are moved is one of the concepts. 

Indeed the challenge can be reduced to 'Columnar Transposition Cipher'.

A short explanation of the alg: 

+ Every line of the file is encrypted indipendently
+ The encryption is performed by ```c=twistedColumnarEncrypt(pt_line, key_n)```
+ A new key is generated for every plaintext message line
+ The challenge provides **the source code used for encryption, the encrypted flag, the last generated key**

Let's see the code - i cut it in part to explain it:
```
# a pseudo random number generator class 
class PRNG:
    def __init__(self, seed):
        self.p = 0x2ea250216d705
        self.a = self.p
        self.b = int.from_bytes(os.urandom(16), 'big')
        self.rn = seed

    def next(self):
        self.rn = ((self.a * self.rn) + self.b) % self.p
        return self.rn

# init
seed = int.from_bytes(os.urandom(16), 'big')
rng = PRNG(seed)

# encryption
for message in SUPER_SECRET_MESSAGES:
  key = str(rng.next())
  ct = twistedColumnarEncrypt(message, key)
  cts += ct + "\n"
```
In this snippet a few critical issues appears:
+ ```p, a, b``` parameters are never updated and in particular ```a = p```
+ The PRNG is reused

For this reason the ```b``` param is our ```rn``` and this vulnerability is repetead everytime a new line is encrypted.
```
# a short example
# you know that (x*y) mod x = 0
# so if you write
# [(x*y) + k mod x] is the same as [k mod x]
```
We know the key used, nice!
```
# derive key - is deterministic!
def deriveKey(key):
    derived_key = []

    for i, char in enumerate(key):
        previous_letters = key[:i]
        new_number = 1
        for j, previous_char in enumerate(previous_letters):
            if previous_char > char:
                derived_key[j] += 1
            else:
                new_number += 1
        derived_key.append(new_number)
    return derived_key

def transpose(array):
    return [row for row in map(list, zip(*array))]

# how the ecnryption is performed
def twistedColumnarEncrypt(pt, key):
    derived_key = deriveKey(key)

    width = len(key)

    blocks = [pt[i:i + width] for i in range(0, len(pt), width)] # step 1
    blocks = transpose(blocks) # step 2

    ct = [blocks[derived_key.index(i + 1)][::-1] for i in range(width)] # step 3
    ct = flatten(ct) # from a list of list create a string
    return ct
```
As our key remain the same the output of ```deriveKey()``` is always the same - and can be ignored.

Using our considerations the possible conclusion is only one: **"we are not decrypting it. we are deciphering it"**

Now debunk ```twistedColumnarEncrypt()``` - i commented the code with every step:

+ Step 1: Create N blocks using ```width = len(key)``` as length.
+ Step 2: Every block is converted from a string to a list and standard trasposition is performed. Every first char of lists become part of the new first block OR every column become a line
```
# visualize
[ a,b,c,d ] => [ a,e ]
[ e,f,g,h ] => [ b,f ]
            => [ c,g ]
            => [ d,h ]
```
+ Step 3.0 : Consider the ```derived_key = [13, 5, 14, 10, 3, 8, 15, 4, 6, 9, 1, 11, 2, 7, 12]```, the first operation is use the derived_key to change block order.
The first new block is the block that were at position ten because the number '1' was at position '10' in the derived_key.
+ Step 3.1 : The block elements are reverse (they are list) and the overall text now is a list of list.

I wrote a script to show how the process work and how to build a ```reverse_order_lists``` key to reverse the block scrumbling:

```
def transpose(array):
    return [row for row in map(list, zip(*array))]

std = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~😀😃😄😁😆😅😂🤣🥲🫁🧠"

key = "729513912306026"

width = len(key)
derived_key = [13, 5, 14, 10, 3, 8, 15, 4, 6, 9, 1, 11, 2, 7, 12]

blocks = [std[i:i + width] for i in range(0, len(std), width)] # every block is 15

blocks = transpose(blocks)
sample = blocks # save this
# print(sample)

blocks = [blocks[derived_key.index(i + 1)][::-1] for i in range(width)]
# print(blocks)


print("-" * 30)

# special case with \\' on block1
print(' ' * 10, 'STEP2', ' ' * 40, 'STEP3')
print(blocks[0], ' |   ', sample[0], end='\n')
for i in range(1,width):
  if any(string in "😂😀😃😄😁😆😅😂🤣🥲🫁🧠" for string in blocks[i]):
    print(blocks[i], '  |   ', sample[i], end='\n')
  else:
    print(blocks[i], '   |   ', sample[i], end='\n')
print("-" * 30)

reverse_order_lists = [0 for i in range(width)]

for i in range(width):
  for b in blocks:
    if b[::-1] == sample[i]:
      reverse_order_lists[blocks.index(b)] = i


# HENYOUARRIVEATTHEPALACEOFSCIONSAYTHECODEPHRASETOGETINHTBTHELCGISVULNERABLEWENEEDTOCHANGEIT
# HTB{THELCGISVULNERABLEWENEEDTOCHANGEIT}

def solve(enc):
	blocks = [[] for i in range(width)]
	z = 1
	a = 1
	
	# preare the list of list from a string line
	for c in enc:
		if a == 105: # string len of scrumbled message
		  break
		# 7 is the length of the block
		if a % 7 == 0: # 107/7 = 15 = key len
		  z += 1
		blocks[z-1].append(c)
		a += 1

	b2 = ['' for i in range(width)]

	got = reverse_order_lists
	for i in range(width):
		b2[i] = blocks[got.index(i)][::-1]

	b2 =  transpose(b2)

	c = ''
	for i in b2:
		c += ''.join(i)

	print("GOT   ::::   ",c)
	
with open('encrypted_messages.txt.bak','r') as f:
	line = f.readline().strip()
	while line:
	  solve(line)
	  line = f.readline().strip()
```
