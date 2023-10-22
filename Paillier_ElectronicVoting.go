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

func SendtoTeller(evts *[][]byte, evt [][]byte, canum int, pubKey *PublicKey) {
	for i := 0; i < canum; i++ {
		(*evts)[i] = AddCipher(pubKey, (*evts)[i], evt[i])
	}
}

func SendtoSpokesman(evts *[][]byte, canum int, privKey *PrivateKey) {
	var err error
	var Winner = 0
	for i := 0; i < canum; i++ {
		(*evts)[i], err = Decrypt(privKey, (*evts)[i])
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("第", i+1, "位候选人获得了", new(big.Int).SetBytes((*evts)[i]), "张选票；")
		if new(big.Int).SetBytes((*evts)[Winner]).Cmp(new(big.Int).SetBytes((*evts)[i])) < 1 {
			Winner = i
		}
	}
	fmt.Println("最终第", Winner+1, "位候选人获得的选票最多，为", new(big.Int).SetBytes((*evts)[Winner]), "张")
	return
}

func main() {
	// 生成一个4096位私钥
	privKey, err := GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Println(err)
		return
	}
	privKey.Lambda = new(big.Int).Mul(privKey.pminusone, privKey.qminusone)
	// 程序开始运行提示
	fmt.Println("**********此程序模拟了基于Paillier算法的匿名电子投票的流程**********")
	fmt.Println("首先每位投票者为候选人投票并将结果加密发送给计票人。每人只有1张选票，\n选票上被投票的候选者得到1张选票，其他候选者得到0张选票；")
	fmt.Println("然后计票人将所有选票上对应候选人的加密的投票结果相乘，并将加密的统计\n结果发送给公布人；")
	fmt.Println("最后公布人对统计的票数进行解密并公布。")
	fmt.Println("********************************************************************")

	fmt.Print("请设置候选者人数：")
	var CandidatesNum int
	fmt.Scan(&CandidatesNum)
	if CandidatesNum <= 0 {
		fmt.Println("候选者人数至少为1")
		return
	}
	EncryptedVotes := make([][]byte, CandidatesNum)
	for i := 0; i < CandidatesNum; i++ {
		EncryptedVotes[i], _, err = Encrypt(&privKey.PublicKey, big.NewInt(int64(0)).Bytes())
	}
	fmt.Print("请设置投票者人数：")
	var VotersNum int
	fmt.Scan(&VotersNum)
	if VotersNum <= 0 {
		fmt.Println("投票者人数至少为1")
		return
	}

	// 投票提示
	for i := 0; i < VotersNum; i++ {
		fmt.Println("-----请第", i+1, "名投票者为候选者投票-----")
		Vote := make([]int, CandidatesNum)
		var flag bool
		for j := 0; j < CandidatesNum; j++ {
			fmt.Print("请为第", j+1, "名候选者投票：")
			fmt.Scan(&Vote[j])
			if Vote[j] == 1 {
				if flag {
					fmt.Println("非法投票！每位投票者只有1张选票！")
					return
				}
				flag = true
			}
		}
		// 将加密的投票结果发给计票人
		EncryptedVote := make([][]byte, CandidatesNum)
		for i := 0; i < CandidatesNum; i++ {
			EncryptedVote[i], _, err = Encrypt(&privKey.PublicKey, big.NewInt(int64(Vote[i])).Bytes())
			if err != nil {
				fmt.Println(err)
				return
			}
		}
		fmt.Println("对该投票结果进行加密并发送给计票人")
		fmt.Println("计票人对此投票结果进行计票")
		SendtoTeller(&EncryptedVotes, EncryptedVote, CandidatesNum, &privKey.PublicKey)
	}

	fmt.Println("-----计票人计票完成并将加密后的投票结果发给公布人-----")
	fmt.Println("加密后的投票结果为：")
	for i := 0; i < CandidatesNum; i++ {
		fmt.Println("第", i+1, "位候选人获得的选票票数的加密结果为", new(big.Int).SetBytes(EncryptedVotes[i]))
	}
	fmt.Println("-----公布人解密计票结果并公布最终的投票结果-----")
	SendtoSpokesman(&EncryptedVotes, CandidatesNum, privKey)
}
