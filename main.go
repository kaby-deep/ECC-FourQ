// https://asecuritysite.com/encryption/go_fourq
package main

import (
	"crypto/rand"
	"fmt"
	"io"
  "encoding/hex"
	"github.com/cloudflare/circl/ecc/fourq"
)

// 32 byte keys used
const Size = 32 // 
type Key [Size]byte

// From secret s, calculate public key (public=aG)
func KeyGen(public, s *Key) {
  var P fourq.Point
  P.ScalarBaseMult((*[32]byte)(s))
  P.Marshal((*[Size]byte)(public))

}

func Shared(shared, secret, public *Key) bool {
	var P, Q fourq.Point
	ok := P.Unmarshal((*[Size]byte)(public))
	Q.ScalarMult((*[Size]byte)(secret), &P)
	Q.Marshal((*[Size]byte)(shared))
	ok = ok && Q.IsOnCurve()
	return ok
}

func main() {

	var AliceSecret, BobSecret,
		AlicePublic, BobPublic,
		AliceShared, BobShared Key

  // Generate Alice's private key and public key
	_, _ = io.ReadFull(rand.Reader, AliceSecret[:32])
	KeyGen(&AlicePublic, &AliceSecret)

  // Generate Bob's private key and public key
	_, _ = io.ReadFull(rand.Reader, BobSecret[:])
	KeyGen(&BobPublic, &BobSecret)

  fmt.Println("Fourq key sharing")
  fmt.Println("Alice Secret: ", hex.EncodeToString(AliceSecret[:32]))
	fmt.Println("Alice Public: ",hex.EncodeToString(AlicePublic[:32]))
  fmt.Println("\n\nBob Secret: ", hex.EncodeToString(BobSecret[:32]))
	fmt.Println("Bob Public: ",hex.EncodeToString(BobPublic[:32]))

	// Determine shared keys
	Shared(&AliceShared, &AliceSecret, &BobPublic)
	Shared(&BobShared, &BobSecret, &AlicePublic)

	fmt.Println("\n\nBob Shared:\t", hex.EncodeToString( BobShared[:32] ))
  fmt.Println("Alice Shared:\t", hex.EncodeToString( AliceShared[:32] ))


}
