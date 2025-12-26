package main

var USAGE = `
  Usage:

	whisper [options] [input file]


  Examples:

	# Encrypt a file for github id jack
	whisper -e @jack hello.txt > hello.wsp

	# Decrypt a file
	whisper hello.wsp

	# Encrypt a file for github id jack and sign as github id tim 
	whisper -s @tim -e @jack hello.txt > hello.wsp

	# Check who is the sender
	whisper -m hello.wsp

	# Decrypt and verify the sign
	whisper -s @tim hello.wsp

	# Batch encryption
	whisper -be whisper.json

	# Batch decryption
	whisper -bd whisper.json

`
