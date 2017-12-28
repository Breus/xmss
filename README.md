[![Build Status](https://travis-ci.org/AidosKuneen/xmss.svg?branch=master)](https://travis-ci.org/AidosKuneen/xmss)
[![GoDoc](https://godoc.org/github.com/AidosKuneen/xmss?status.svg)](https://godoc.org/github.com/AidosKuneen/xmss)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/AidosKuneen/xmss/master/LICENSE)


XMSS (eXtended Merkle Signature Scheme)
=====

## Overview

This library is for creating keys, signing messages and verifing the signature by XMSS in golang.

This code implements XMSS-SHA2_10_256, 
XMSS-SHA2_16_256, XMSS-SHA2_20_26 described on IRTF draft [XMSS: Extended Hash-Based Signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-xmss-hash-based-signatures/) and 
compatible with [XMSS reference code](https://github.com/joostrijneveld/xmss-reference).
But this code is much faster than the reference code by using [SSE extention](https://github.com/minio/sha256-simd) and block level optimizations in sha256,
with multi threadings.


## Requirements

* git
* go 1.9+

are required to compile.


## Install
    $ go get -u github.com/AidosKuneen/xmss


## Usage

```go
	import "github.com/AidosKuneen/xmss"
	seed := []byte{0x01,0x02...}
	mer := xmss.NewMerkle(10, seed)
	msg := []byte("This is a test for XMSS.")
	sig := mer.Sign(msg)
	pub := mer.PublicKey()
	if !xmss.Verify(sig, msg, pub) {
		log.Println("signature is invalid")
	}
	//output Merkle contents to json
	dat, err := mer.MarshalJSON()
	//convert json to Merkle
	mer2 := xmss.Merkle{}
    err := mer2.UnmarshalJSON(dat)
```

## Performance

Using the following test environment...

```
* Compiler: go version go1.9.1 linux/amd64
* Kernel: Linux WS777 4.13.5-1-ARCH #1 SMP PREEMPT Fri Oct 6 09:58:47 CEST 2017 x86_64 GNU/Linux
* CPU:  Celeron(R) CPU G1840 @ 2.80GHz 
* Memory: 8 GB
```


For XMSS-SHA2_10_256, it takes 

* about 0.87 seconds to generating a keypair,
* about 6.7 mS to sign a message,
* about 720 uS to verify a signature.

For XMSS-SHA2_16_256, it takes 

* about 55 seconds to generating a keypair,
* about 7.2 mS to sign a message,
* about 680 uS to verify a signature.


```
BenchmarkXMSS10-2       	       2	 871073106 ns/op
BenchmarkXMSS10Sign-2   	     200	   6680257 ns/op
BenchmarkXMSS10Veri-2   	    2000	    716316 ns/op
BenchmarkXMSS16-2       	       1	54495501572 ns/op
BenchmarkXMSS16Sign-2   	     200	   7239790 ns/op
BenchmarkXMSS16Veri-2   	    2000	    677960 ns/op
```

on DIGNO M KYL22(Android Smartphone):

```
* Compiler: go version go1.9.1 linux/arm
* OS: 	Android 4.2.2
* CPU:	Qualcomm Snapdragon 800 MSM8974 2.2GHz (quad core)
* Memory: 2 GB
```


For XMSS-SHA2_10_256, it takes 

* about 9.1 seconds to generating a keypair,
* about 52 mS to sign a message,
* about 4.4 mS to verify a signature.

```
BenchmarkXMSS10     	       1	9140479008 ns/op
BenchmarkXMSS10Sign 	     100	  51787360 ns/op
BenchmarkXMSS10Veri 	     300	   4368742 ns/op
```

on a cloud server:

* Compiler: go version go1.8.1 linux/amd64
* Kernel: Linux 4.8.0-58-generic #63~16.04.1-Ubuntu SMP Mon Jun 26 18:08:51 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
* CPU:  CAMD Ryzen 7 1700X Eight-Core Processor @ 2.20GHz (8 cores)
* Memory: 64 GB


For XMSS-SHA2_10_256, it takes 

* about 0.46 seconds to generating a keypair,
* about 4.5 mS to sign a message,
* about 450 uS to verify a signature.

For XMSS-SHA2_16_256, it takes 

* about  29 seconds to generating a keypair,
* about  4.4 mS to sign a message,
* about  510 uS to verify a signature.


For XMSS-SHA2_20_256, it takes 
about  8.5 minutes to generating a keypair,


```
BenchmarkXMSS10-16        	2000000000	         0.23 ns/op
BenchmarkXMSS10Sign-16    	     500	   4457839 ns/op
BenchmarkXMSS10Veri-16    	    3000	    453052 ns/op
BenchmarkXMSS16-16        	       1	29257509692 ns/op
BenchmarkXMSS16Sign-16    	     500	   4250762 ns/op
BenchmarkXMSS16Veri-16    	    3000	    492381 ns/op
BenchmarkXMSS20-16        	       1	510150155087 ns/op
```
