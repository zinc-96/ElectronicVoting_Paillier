package main


import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
)

var one = big.NewInt(1)

// ErrMessageTooLong 当所需加密信息长度大于公钥长度时，报错。
var ErrMessageTooLong = errors.New("信息过长！请调整公钥长度！")

// GenerateKey 生成指定位数的公私钥。
func GenerateKey(random io.Reader, bits int) (*PrivateKey, error) {
	// 生成素数p
	var p *big.Int
	var errChan = make(chan error, 1)
	go func() {
		var err error
		p, err = rand.Prime(random, bits/2)
		errChan <- err
	}()

	// 生成素数q
	q, err := rand.Prime(random, bits/2)
	if err != nil {
		return nil, err
	}

	// 等待素数p生成完成
	if err := <-errChan; err != nil {
		return nil, err
	}
	n := new(big.Int).Mul(p, q)
	pp := new(big.Int).Mul(p, p)
	qq := new(big.Int).Mul(q, q)

	return &PrivateKey{
		PublicKey: PublicKey{
			N:        n,
			NSquared: new(big.Int).Mul(n, n),
			G:        new(big.Int).Add(n, one), // g = n + 1
		},
		p:         p,
		pp:        pp,
		pminusone: new(big.Int).Sub(p, one),
		q:         q,
		qq:        qq,
		qminusone: new(big.Int).Sub(q, one),
	}, nil

}

// PrivateKey 私钥
type PrivateKey struct {
	PublicKey
	p         *big.Int
	pp        *big.Int
	pminusone *big.Int
	q         *big.Int
	qq        *big.Int
	qminusone *big.Int
	Lambda    *big.Int
}

// PublicKey 公钥
type PublicKey struct {
	N        *big.Int
	G        *big.Int
	NSquared *big.Int
}

// L L(x)=(x-1)/n
func L(x, n *big.Int) *big.Int {
	return new(big.Int).Div(new(big.Int).Sub(x, one), n)
}

// Encrypt 加密。
func Encrypt(pubKey *PublicKey, plainText []byte) ([]byte, *big.Int, error) {
	r, err := rand.Int(rand.Reader, pubKey.N)
	if err != nil {
		return nil, nil, err
	}

	m := new(big.Int).SetBytes(plainText)
	if pubKey.N.Cmp(m) < 1 { // N < m
		return nil, nil, ErrMessageTooLong
	}

	// c = g^m * r^n mod n^2 = [(m*n+1) mod n^2] * r^n mod n^2
	c := new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Mod(new(big.Int).Add(one, new(big.Int).Mul(m, pubKey.N)), pubKey.NSquared),
			new(big.Int).Exp(r, pubKey.N, pubKey.NSquared),
		),
		pubKey.NSquared,
	)

	return c.Bytes(), r, nil
}

// Decrypt 解密。
func Decrypt(privKey *PrivateKey, cipherText []byte) ([]byte, error) {
	c := new(big.Int).SetBytes(cipherText)
	if privKey.NSquared.Cmp(c) < 1 {
		return nil, ErrMessageTooLong
	}
	mu := new(big.Int).ModInverse(privKey.Lambda, privKey.N)
	m := new(big.Int).Mod(new(big.Int).Mul(L(new(big.Int).Exp(c, privKey.Lambda, privKey.NSquared), privKey.N), mu), privKey.N)
	return m.Bytes(), nil
}

// AddCipher 将两个密文相乘，以达到明文相加的目的。
func AddCipher(pubKey *PublicKey, cipher1, cipher2 []byte) []byte {
	x := new(big.Int).SetBytes(cipher1)
	y := new(big.Int).SetBytes(cipher2)
	// x * y mod n^2
	return new(big.Int).Mod(new(big.Int).Mul(x, y), pubKey.NSquared).Bytes()
}

func main() {
	// 生成一个4096位私钥
	privKey, err := GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Println(err)
		return
	}
	privKey.Lambda = new(big.Int).Mul(privKey.pminusone, privKey.qminusone)
	// 加密明文1
	fmt.Print("请输入第一个明文：")
	var Plaintext1 big.Int
	fmt.Scan(&Plaintext1)
	Cipher1, _, err := Encrypt(&privKey.PublicKey, Plaintext1.Bytes())
	if err != nil {
		fmt.Println(err)
		return
	}

	// 加密明文2
	fmt.Print("请输入第二个明文：")
	var plaintext2 big.Int
	fmt.Scan(&plaintext2)
	Cipher2, _, err := Encrypt(&privKey.PublicKey, plaintext2.Bytes())
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("对第一个明文加密后得到密文：", new(big.Int).SetBytes(Cipher1))
	fmt.Println("对第二个明文加密后得到密文：", new(big.Int).SetBytes(Cipher2))

	// 将明文1与明文2相加。
	EncryptedPlusCipher1Cipher2 := AddCipher(&privKey.PublicKey, Cipher1, Cipher2)
	fmt.Println("两密文相乘得到：", new(big.Int).SetBytes(EncryptedPlusCipher1Cipher2))
	DecyptedPlusCipher1Cipher2, err := Decrypt(privKey, EncryptedPlusCipher1Cipher2)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("密文相乘后解密得到的明文为：", new(big.Int).SetBytes(DecyptedPlusCipher1Cipher2))
}
