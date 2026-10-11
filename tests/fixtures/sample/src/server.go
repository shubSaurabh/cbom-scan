package main

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/mlkem"
)

func setup() {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	cfg := &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}}
	dk, _ := mlkem.GenerateKey768()
}
