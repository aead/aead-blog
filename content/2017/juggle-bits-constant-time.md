+++
title = "How to juggle with bits in constant time"
date = "2017-05-29"
menu = "main"
tags = ["Cryptography", "Go", "Assembly", "BoringSSL"]
+++

Simple tasks can be surprisingly difficult when cryptography is involved. Imagine a function
which takes two byte arrays/slices and tells us whether the arrays/slices are equal - how hard 
can that be?

It turns out that there are several pitfalls we must work around. Today I want to give a little overview
about how to implement commonly used functions in constant time - an important property within the context
of cryptography. Furthermore I briefly show how to speed-up such implementations with a real-world example
that made it into Google's BoringSSL library.

Conceptually there are two different approaches how to implement functionality in constant time. The first one uses
bit arithmetic, often used for comparing arrays/slices or strings. The second one exploits some special CPU
instructions like CMOV (conditional move) to prevent timing-leaks caused by branch prediction failures on modern
processors.  

### Bit arithmetic

An important function used by various cryptographic libraries is the *constant time compare*. Typically it takes
two byte arrays/slices and tells the caller whether the array/slices are equal. One way to implement this is to
first check that the length of both arrays/slices is equal.
```
func ConstantTimeCompare(a, b []byte) int {
   if len(a) != len(b) {
       return 0 // we return 1 iff both slices are equal, 0 otherwise
   }
   // ... 
}
```
Then we compare the content of both slices. Therefore we compute the difference byte for byte and store this difference.
If both slices are equal the difference must be zero at the end.
```
func ConstantTimeCompare(a, b []byte) int {
   if len(a) != len(b) {
       return 0 // we return 1 iff both slices are equal, 0 otherwise
   }
   
   var c byte
   for i := 0; i < len(a); i++ {
       c |= (a[i] ^ b[i]) // a[i] ^ b[i] is only zero if a[i] == b[i]
   }
   // ... 
}
```
The last thing to do is to check whether c is equal to zero.
```
func ConstantTimeCompare(a, b []byte) int {
   if len(a) != len(b) {
       return 0 // we return 1 iff both slices are equal, 0 otherwise
   }
   
   var c byte
   for i := 0; i < len(a); i++ {
       c |= (a[i] ^ b[i]) // a[i] ^ b[i] is only zero if a[i] == b[i]
   }
   
   c = ^c
   c &= c >> 4
   c &= c >> 2
   c &= c >> 1
   
   return int(c)
}
```
Remember: `ConstantTimeCompare` returns 1 if and only if both slices are equal, otherwise it returns 0.
So we build the complement of `c` which will be `0xff` if `c` is zero. The `&` and `>>` sequence ensures
that `c` is only equal to 1 if the complement of `c` has all bits set (`0xff`).  
This is how the `ConstantTimeCompare` function in Go's [crypto/subtle](https://golang.org/src/crypto/subtle/) package works.

Comparing sensitive data, like message authentication codes, this way is absolutely fine and highly recommended but if our
constant time algorithm is part of a performance critical construction we may want to implement it in assembly. Of course we
can use bit arithmetic in assembly as well but there is also another technique.

### Conditional instruction - CMOV

To understand how we can implement constant time algorithms with conditional instructions we have to know how modern processors 
execute instructions first - no panic just conventionally :wink: - I will omit many details now to keep things simple.  
A modern CPU tries to execute one (or more) instruction per clock signal. Unfortunately the processor must fetch and decode 
every instruction before it can be executed. The fetching and decoding takes time and slows the CPU down. Therefore CPU-designers
introduced the concept of a pipeline. The pipeline holds executable instructions and the CPU consumes one instruction after the other. This 
works quite well until a branch instruction, like a jump, occurs. Now the processor does not know which instructions should be put into the pipeline.
To work this around there is a mechanism called branch prediction. The processor "guesses" which branch it should follow and fills the
pipeline with the corresponding instructions.  
Of course if it turns out that the "guess" was wrong the CPU cannot proceed - the CPU must empty the pipeline and than load the correct 
instructions. This takes a long time and leaks information about the processed data. Luckily many instruction sets provide conditional instructions.
These instructions are only executed if certain flags are set.
```
movq $0xcafe, %rax
movq $0xbabe, %rbx

cmp   $42,  $rcx 
movq  %rax, %rdx
cmove %rbx, %rax
cmove %rdx, %rbx
```
This few x64 assembly instructions put `0xcafe` into the `AX` register, `0xbabe` into the `BX` register and swap the values if the `CX` register
is equal to 42. Both cmove instructions will only be executed if the value in `CX` is 42. Of course it is not really useful to swap `0xcafe` and
`0xbabe` but we achieved this without any branch instruction. Now we can look at a much more practical example.

### Curve25519 and cswap

Elliptic curves are commonly used in modern cryptographic protocols - actually good news :tada:. If you are not familiar with elliptic curves you
may want to check out an awesome [introduction](https://media.ccc.de/v/31c3_-_6369_-_en_-_saal_1_-_201412272145_-_ecchacks_-_djb_-_tanja_lange) by 
Daniel Bernstein and Tanja Lange.  
If you are familiar with ECC you probably know that there is a curve called Curve25519 which is used in TLS and you may also know that many
implementations of this curve use a conditional swap (cswap) subroutine - also Go's Curve25519 implementation do. The cswap function takes two 
points of the curve and conditionally swaps them. To do this efficiently Go's implementation used a cmov assembly scheme on the amd64 platform. 

I looked at the implementation and thought: "This cmov scheme is actually complicated - maybe I can do this more like the non-assembly code".
After some failed attempts I ended up with this:
```
SUBQ $1, SI
NOTQ SI
MOVQ SI, X15
PSHUFD $0x44, X15, X15

MOVOU 0(DI),  X0
MOVOU 80(DI), X1

MOVO X1,  X2

PXOR X0,  X2
PAND X15, X2
PXOR X2,  X0
PXOR X2,  X1

MOVOU X0, 0(DI)
MOVOU X1, 80(DI)
```
This is not the complete implementation but it shows the principle. The condition (stored in `SI`) is used to generate an AND mask - the xmm15 register.
Then I load the first 16 bytes of the coordinates into the xmm0 / xmm1 registers and exploit a nice bit arithmetic rule:
```
t := (x ^ y) & m
if m == 1 than x ^ t = y and y ^ t = x
if m == 0 than x ^ t = x and y ^ t = y
```
This is basically what I wanted to do. :tada: So I applied this scheme to all coordinate bytes and it turned out: They fit perfectly into the 16 XMM registers - every
amd64 CPU must provide 16 XMM registers. :tada: :tada: 
But is this faster than the previous cmov scheme? Yes it is - at least on my machines about 40%. So I submitted this as [CL](https://go-review.googlesource.com/c/39693/)
to the Go team and Adam Langley reviewed and accepted it. So I successfully improved a commonly used cryptographic primitive - yeah. :muscle:  
But I have not thought a second about whether there are other Curve25519 implementations which can be improved the same way - or even other elliptic curves. This took
more than a month. I have no clue why I suddenly thought: "Hey what about other Curve25519 implementations - can I improve them, too?"  
Maybe it was a [Tavis-shower-moment](https://twitter.com/taviso/status/845717082717114368). :wink: 

So my first thought was OpenSSL. Unfortunately they do not provide any assembly implementation of Curve25519. My second thought was: "Okay, Adam Langley has written Go's 
Curve25519 implementation - what other implementation is mainly developed by Adam? To which TLS library are you talking to whenever you google something?"   
Right, I looked at the cswap [implementation](https://boringssl.googlesource.com/boringssl/+/d94682dce5263e11bacd47e8d33e77c0315eac5c/crypto/curve25519/asm/x25519-asm-x86_64.S)
of BoringSSL and it was identical to the one I patched at Go. So I basically copied and adjusted my Go assembly code and send the [patch](https://boringssl.googlesource.com/boringssl/+/e7d3922b437e6e973b8d9202f6bebfd5074a682b%5E%21/#F0) to the BoringSSL repository. Adam reviewed the change again and voted
with LTGM - so the patch got merged, so far so good.

### Future work

But there is still some work to do. Go and BoringSSL use this technique now and I know that Go's P-256 implementation does something similar but there are many other
implementations out there which should be checked.  
I have looked at:

 - [ring](https://github.com/briansmith/ring/blob/master/crypto/curve25519) which uses BoringSSL and will get the code through an update - I guess
 - [OpenSSL](https://github.com/openssl/openssl/tree/master/crypto/ec) which does not provide any Curve25519 assembly implementations
 - [LibreSSL](https://github.com/libressl-portable/openbsd/tree/master/src/lib/libcrypto/curve25519) also no Curve25519 assembly implementations
 - [NSS](https://github.com/nss-dev/nss/blob/b92d9aa631801620193ed07830295c3750aa6386/lib/freebl/ecl/curve25519_64.c) also no Curve25519 assembly implementations

So if you are familiar with ECC and have some experience in writing assembler and you way want to help them out, they need you!