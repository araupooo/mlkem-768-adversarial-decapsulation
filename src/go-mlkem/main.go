// Go stdlib crypto/mlkem driver (ML-KEM-768, FIPS 203).
// Commands on stdin, one per line:
//   keygen            -> PK <hex ek 1184B> DK <hex dk 2400B>
//   encap <hex ek>    -> CT <hex ct 1088B> SS <hex ss 32B>
//   decap <hex dk> <hex ct> -> SS <hex ss 32B> | ERR <message>
//   version           -> VERSION <go version> MLKEM768
package main

import (
	"bufio"
	"crypto/mlkem"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
)

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	fmt.Println("READY go=" + runtime.Version())
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "version":
			fmt.Println("VERSION go=" + runtime.Version() + " mlkem=stdlib crypto/mlkem ML-KEM-768 FIPS-203")
		case "keygen":
			dk, err := mlkem.GenerateKey768()
			if err != nil {
				fmt.Println("ERR", err)
				continue
			}
			fmt.Printf("PK %x DK %x\n", dk.EncapsulationKey().Bytes(), dk.Bytes())
		case "encap":
			if len(f) != 2 {
				fmt.Println("ERR encap needs ek hex")
				continue
			}
			ekb, err := hex.DecodeString(f[1])
			if err != nil {
				fmt.Println("ERR bad ek hex:", err)
				continue
			}
			ek, err := mlkem.NewEncapsulationKey768(ekb)
			if err != nil {
				fmt.Println("ERR bad ek:", err)
				continue
			}
			ss, ct := ek.Encapsulate()
			fmt.Printf("CT %x SS %x\n", ct, ss)
		case "decap":
			if len(f) != 3 {
				fmt.Println("ERR decap needs dk ct hex")
				continue
			}
			dkb, err := hex.DecodeString(f[1])
			if err != nil {
				fmt.Println("ERR bad dk hex:", err)
				continue
			}
			ct, err := hex.DecodeString(f[2])
			if err != nil {
				fmt.Println("ERR bad ct hex:", err)
				continue
			}
			dk, err := mlkem.NewDecapsulationKey768(dkb)
			if err != nil {
				fmt.Println("ERR bad dk:", err)
				continue
			}
			ss, err := dk.Decapsulate(ct)
			if err != nil {
				fmt.Println("ERR decap:", err)
				continue
			}
			fmt.Printf("SS %x\n", ss)
		default:
			fmt.Println("ERR unknown command")
		}
	}
}
