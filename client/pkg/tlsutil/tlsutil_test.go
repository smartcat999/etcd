package tlsutil

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"
)

func TestAES256CBCExample01(t *testing.T) {
	encryKey := `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,BA9C8341E29725A4FAC0A365C298D653

3Xw8R+JsAVQhEb57EpZUd7Wa/QZ1OqCGl++ZIZ7PbG9wteIn6C0L3+Yo1pZDMnCN
dKuhndiYlLmIfrYmZtye5r9f2IYYizseAmFNag+f5e7kalUAqQUTT/soUBHEg5uu
5u0W1NAioxZfnmrdd19+0lCp4Qbw1eV2Grh18NUJ2kWI4pK9QtxrgEdh1Zbr8u10
ijqf/C+Xg3OZi/53zw147IRJbTSSUYdYCbE7V8Ii4EgmRD9QTaeTTn8HT07agaeR
NfnWTYL5yTB551t4Ofogfzq8m3rlB1K1eQhVHdXxdZxl06iaK4CStiLAvrXBA5j9
GOmGLZCtddoeJi7gUsO6Oqc4CIVhgXxejm3i8ACc4zPO7U/S1q+Ck64gVV2kFEK/
1NdBdlpSy4IsThr5tGMNr1yYeHHbK99uqtKIUwHLckUYQtVu9cScx9ABX+aNZv2D
O2BVAd/asEdezS9GSPNtmPQoRNGqnpBpOMT0TikGSeSsbobdMUVIcbqVV0A8ogzi
WgPtUtwCPgLbYuJauqzwOVS9ErohefVHBV4+p4/Oa140fc8iEqLilVZgGLBZJJGB
PgXmit+LKJzuzE6oqpiMs9T4BDWqFEHTcTNbdOezzDOCrYPFn7IinOLU4HPm7Tmn
B4fP2YaR35bJKWYvjwxTwOcMTunl3BFxguoCpy6OPMgxWc875VKLGXJc4zOuiX6o
nhq+26iQ2mIWylYZcj00H7ial/czoKTTZuGT0uK2vq97OHnKBt5GH1nYqOoHofIw
BhR1OJWffzpTBzTjaLNOtIU2XTAZmeJlV7UB0Crgs7zUVLnofNhAmgkMGKZxKGfJ
S4h8FVz13mXQw5O4hODRKIbDbcA2Cy4MUOhgCSR5sumfsKeJ/o4B9Dyzhguxl8Sb
JosLFDsSF7f870TUO/oldngBhZqPVBuAD+tNl4VTcfqv1eDaQglb6wJ61TXiGIeV
Mm+doMX160BO/e5wdKMq6dOzREEy+QKm8LA1JqVKqb0N0Tollyf0/Lo5p/SXbqeF
5Kvyd/AxXTkSsKEt0eChZXX3SNzydKbSMqNsqzkST/1YiIulXtenhZrrNMdGnoJP
EaGd+ANdQ28y97E+OoIVP/8qykuwTPSpsu/2TXxoESpHuBRZOzzgGTFBaUXyXbT4
FJXTI0jghY8or5JkNW7JGAOMuQ8jQHnJNdyPFEBVbCjE4rZ+cuBBxCfracxehmw8
Q0bBdrFzVWye+0b1fJP0jtMQVvmbReOt9EDJ8IZPRXuFFnON4pnJI89VAPXXemgX
o+W90kIA3lFNJNKRHA5A82jYfxfdHezh/jVSuW3PnQu3SbpHhdpgJRokTVLFLx+Q
aPzvWZnH8LtH63XLdZUsHqZvTEjH5hA4/sptQPlaeh3lYbDujcasRDAglQouXU33
ZEbFbSjahO28ZE6NZeGZsRqoiHeJ6CmgMxabHlJOMtf76aUGVezo8VfLOHSQ01Tn
q42BURh9TNHChMQOIpwB/MOAe6UYKRdbTGXR1Db/6HieDn8In7pTNfY0tLdFm6gS
VvUbhwjHvQ8wI1dvd5+BH+i2S+4dhAm1jyyxOyj6XXd9WC8SsvcUKDpRfYWNb2at
-----END RSA PRIVATE KEY-----`
	key, err := ParseRSAPrivateKeyFromPEMWithPassword([]byte(encryKey), "test")
	if err != nil {
		t.Logf("ParseRSAPrivateKeyFromPEMWithPassword Err: %v", err)
	}
	t.Logf("origin data: %v", key)
	keybytes := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keybytes,
	}
	privateKey := pem.EncodeToMemory(block)
	t.Logf("MarshalPKCS1PrivateKey: %v", string(privateKey))
}

func TestAES256GCMExample01(t *testing.T) {
	plaintext := "test"
	key := "6368616e676520746869732070617373776f726420746f206120736563726574"
	cipherKey, err := hex.DecodeString(key)
	if err != nil {
		panic(err)
	}
	nonce := hex.EncodeToString(cipherKey[:12])
	t.Logf("key: %s", key)
	t.Logf("nonce: %s", nonce)

	encryptData, err := Encrypt([]byte(plaintext), key)
	if err != nil {
		panic(err)
	}
	t.Log(encryptData)

	originData, err := Decrypt(encryptData, key)
	if err != nil {
		panic(err)
	}
	t.Log(string(originData))
}
