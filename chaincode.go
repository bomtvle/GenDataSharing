package main

import (
	"fmt"
	"crypto/rand"
	"time"
	/*
	"io/ioutil"
    	"log"
	*/
	"go.dedis.ch/kyber/v3"
	//"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/util/random"
	
)

func pow(b string) int {
	var hashInt big.Int
	var hash [32]byte

	target := big.NewInt(1)
	target.Lsh(target, uint(256-targetBits))

	nonce := 0

	// t1 := time.Now() // get current time
	for nonce < maxNonce {
		data := prepareData(nonce, b)

		hash = sha256.Sum256(data)
		// fmt.Printf("#%d = %x\r", nonce, hash)
		hashInt.SetBytes(hash[:])

		if hashInt.Cmp(target) == -1 {
			// elapsed := time.Since(t1)
			// fmt.Print("\nApp elapsed: ", elapsed)
			break
		} else {
			nonce++
		}
	}

	return nonce
}

func GenerateRandomBytes(n int) []byte {
	
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func RandomData(num int) [][]byte {
	
	token := make([]byte, 10000000)
	
	rand.Read(token)
	ans := make([][]byte,num)
	
	for i := 0 ; i < num ; i++{
		ans[i] = make([]byte,10000000)
	}
	
	for i := 0 ; i < num ; i++{
		ans[i] = GenerateRandomBytes(10000000)
	}
	return ans
}


func main() {
	Num := 300
	Datas := RandomData(Num)
	suite := bn256.NewSuite()

	Privates := []kyber.Scalar{}
	Publics := []kyber.Point{}

	for i := 0 ; i < Num ; i++{
		a,b := bls.NewKeyPair(suite, random.New())
		Privates = append(Privates, a)
		Publics = append(Publics, b)
	}

	start := time.Now()

	sign1, errors := bls.Sign(suite, Privates[0],Datas[0])
	sign2, errors := bls.Sign(suite, Privates[1],Datas[1])

	Signs, errors := bls.AggregateSignatures(suite,sign1,sign2)
	
	// fmt.Println(Signs)
	for i := 2 ; i < Num ; i++ {
		sign1, errors := bls.Sign(suite, Privates[i],Datas[i])
		Signs, errors = bls.AggregateSignatures(suite,Signs,sign1)
		if errors != nil {
			fmt.Println("Aggregate error!")
		}	
		// fmt.Println(Signs)
	}

	// fmt.Println(Signs)

	if errors != nil {
		fmt.Println("BLS-Signature error!")
	}

	/*
	BatchPublic := bls.AggregatePublicKeys(suite,Publics[0],Publics[1])

	for i := 2 ; i < Num ; i++ {
		BatchPublic = bls.AggregatePublicKeys(suite,BatchPublic,Publics[i])
	}

	// fmt.Println(BatchPublic)

	
	/* // msg should be same
	if bls.Verify(suite,Public,msg1,Signs) == nil {
		fmt.Println("BLS-Signature Verify Successful!")
	} else {
		fmt.Println("BLS-Signature Verify Failed!")
	}
	*/
	
	
	if bls.BatchVerify(suite,Publics,Datas,Signs) == nil {
		fmt.Println("BLS-Signature BatchVerify Successful!")
	} else {
		fmt.Println("BLS-Signature BatchVerify Failed!")
	}

	end := time.Since(start)
	fmt.Println(Num,"筆資料簽帳驗證完成時間:",end)
	
}
