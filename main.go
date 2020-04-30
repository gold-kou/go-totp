package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

const (
	digit = 10 // the digit of password
	sharedSecret = ""
	t0 = int64(0)
	timeStepX = int64(30)
)

// input: private key and counter
// output: MAC
func hmacSha512(key []byte, counter uint64) []byte {
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)
	hm := hmac.New(sha512.New, key)
	hm.Write(counterBytes)
	return hm.Sum(nil)
}

// generate one-time-password from MAC
func truncate(hmacResult []byte) uint64 {
	// マスク(00001111=0XF)をかけて末尾4bitを抜き出したものがoffset
	offset := hmacResult[len(hmacResult)-1] & 0xF
	// マスク（0x7FFFFFFF）をかけて終端31bitを抜き出したものがbinCode
	binCode := binary.BigEndian.Uint32(hmacResult[offset:offset+8]) & 0x7FFFFFFF
	// binCodeを10^10で割った余りがpassword
	return uint64(binCode) % uint64(math.Pow10(digit))
}

func hotp(key []byte, counter uint64) uint64 {
	return truncate(hmacSha512(key, counter))
}

func totp(key []byte, t0 int64, x int64) uint64 {
	return hotp(key, uint64((time.Now().Unix() - t0) / x))
}

func main() {
	privateKey := []byte(sharedSecret)
	fmt.Printf("%010d", totp(privateKey, t0, timeStepX))
}