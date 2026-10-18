package keystore_test

// RFC 8032 section 7.1 Ed25519 test vectors, run through the real library: the secret
// seed goes in as a PKCS#8 key built byte by byte here (not by x509), is encrypted into a
// ring, and the signing path must return the RFC's public key and the RFC's signature
// exactly. Ed25519 is deterministic, so the signature is a fixed known answer.
//
// The vector bytes were extracted from https://www.rfc-editor.org/rfc/rfc8032.txt (section
// 7.1, fetched 2026-10-19) by a script, and cross-checked against a second source:
// $GOROOT/src/crypto/ed25519/testdata/sign.input.gz (go1.27.2) contains TEST 1, 2 and 3
// with identical seed, public key, message and signature. That file has no counterpart for
// TEST 1024 and TEST SHA(abc); those two are checked here against the standard library's
// own Ed25519 (sign from seed, and for SHA(abc) the message is recomputed as SHA-512("abc")),
// which is a derivation rather than a second published source. Note the RFC's "TEST 1024"
// message is 1023 bytes long, as the RFC itself states.

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/netstar-labs/keystore/internal/kdf"
	"github.com/netstar-labs/keystore/pkg/keystore"
)

type rfcVector struct {
	name                string
	seed, pub, msg, sig string // hex
}

var rfc8032Vectors = []rfcVector{
	{
		name: "TEST 1",
		seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		pub:  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
		msg:  "",
		sig:  "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
	},
	{
		name: "TEST 2",
		seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
		pub:  "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
		msg:  "72",
		sig:  "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
	},
	{
		name: "TEST 3",
		seed: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
		pub:  "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
		msg:  "af82",
		sig:  "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
	},
	{
		name: "TEST 1024",
		seed: "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
		pub:  "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
		msg: "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1" +
			"e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d" +
			"658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a" +
			"7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e" +
			"06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc10" +
			"3b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1" +
			"85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d" +
			"502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270" +
			"88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089b" +
			"eccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba" +
			"b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969b" +
			"e3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7" +
			"51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988d" +
			"cda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df" +
			"f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7" +
			"984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4" +
			"88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac09" +
			"43bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f" +
			"b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f161" +
			"0e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d" +
			"b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8ca" +
			"c60c905c15fc910840b94c00a0b9d0",
		sig: "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
	},
	{
		name: "TEST SHA(abc)",
		seed: "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
		pub:  "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
		msg:  "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
		sig:  "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
	},
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// pkcs8FromSeed builds the RFC 8410 PrivateKeyInfo for an Ed25519 seed by hand:
// SEQUENCE(46) { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING(34) { OCTET STRING(32) seed } }.
func pkcs8FromSeed(seed []byte) []byte {
	return append(unhexMust("302e020100300506032b657004220420"), seed...)
}

// spkiFromPub builds the SubjectPublicKeyInfo for an Ed25519 public key by hand:
// SEQUENCE(42) { SEQUENCE { OID 1.3.101.112 }, BIT STRING(33) { 0 unused bits, pub } }.
func spkiFromPub(pub []byte) []byte {
	return append(unhexMust("302a300506032b6570032100"), pub...)
}

func unhexMust(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestKATRFC8032Sanity(t *testing.T) {
	if len(rfc8032Vectors) != 5 {
		t.Fatalf("%d vectors, want 5", len(rfc8032Vectors))
	}
	// The embedded bytes agree with the standard library's Ed25519 (a second implementation).
	for _, v := range rfc8032Vectors {
		seed, pub, msg, sig := unhex(t, v.seed), unhex(t, v.pub), unhex(t, v.msg), unhex(t, v.sig)
		priv := ed25519.NewKeyFromSeed(seed)
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
			t.Errorf("%s: stdlib public key differs from the embedded RFC key", v.name)
		}
		if !bytes.Equal(ed25519.Sign(priv, msg), sig) {
			t.Errorf("%s: stdlib signature differs from the embedded RFC signature", v.name)
		}
		if !ed25519.Verify(pub, msg, sig) {
			t.Errorf("%s: RFC signature does not verify", v.name)
		}
	}
	wantLen := map[string]int{"TEST 1": 0, "TEST 2": 1, "TEST 3": 2, "TEST 1024": 1023, "TEST SHA(abc)": 64}
	for _, v := range rfc8032Vectors {
		if got := len(unhex(t, v.msg)); got != wantLen[v.name] {
			t.Errorf("%s: message is %d bytes, RFC says %d", v.name, got, wantLen[v.name])
		}
	}
	sum := sha512.Sum512([]byte("abc"))
	if hex.EncodeToString(sum[:]) != rfc8032Vectors[4].msg {
		t.Error("TEST SHA(abc) message is not SHA-512(\"abc\")")
	}
}

func TestKATRFC8032(t *testing.T) {
	pass := []byte("rfc 8032 passphrase")
	for _, v := range rfc8032Vectors {
		t.Run(v.name, func(t *testing.T) {
			seed, pub, msg, sig := unhex(t, v.seed), unhex(t, v.pub), unhex(t, v.msg), unhex(t, v.sig)

			// The import side: a PKCS#8 PEM holding just the seed.
			der := pkcs8FromSeed(seed)
			privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
			priv, err := keystore.ParsePrivateKeyPEM(privPEM)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(priv.Seed(), seed) {
				t.Fatal("parsed key has a different seed")
			}

			path := filepath.Join(t.TempDir(), "r.ks")
			k, err := keystore.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := k.Import("rfc", priv, pass); err != nil {
				t.Fatal(err)
			}

			// Check through the original handle and through a fresh Open of the file, so
			// both the in-memory ring and what was written to disk give the RFC answers.
			k2, err := keystore.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			for name, ks := range map[string]*keystore.Keystore{"created": k, "reopened": k2} {
				gotPub, err := ks.Public("rfc")
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(gotPub, pub) {
					t.Fatalf("%s: Public = %x, RFC %x", name, gotPub, pub)
				}
				s, err := ks.Signer("rfc", pass)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(s.Public().(ed25519.PublicKey), pub) {
					t.Fatalf("%s: Signer public key differs from the RFC key", name)
				}
				// Ed25519 takes the whole message (hash must be crypto.Hash(0)); rand is unused.
				got, err := s.Sign(rand.Reader, msg, crypto.Hash(0))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, sig) {
					t.Fatalf("%s: Sign = %x\n want %x", name, got, sig)
				}
				// The current key (id "") is the same key.
				s2, err := ks.Signer("", pass)
				if err != nil {
					t.Fatal(err)
				}
				if got, _ := s2.Sign(nil, msg, crypto.Hash(0)); !bytes.Equal(got, sig) {
					t.Fatalf("%s: current-key signature differs", name)
				}
				if !ed25519.Verify(gotPub, msg, sig) {
					t.Fatalf("%s: RFC signature does not verify under Public", name)
				}
			}

			// Export round trip: PKCS#8 for an Ed25519 key is deterministic, so exporting the
			// key must reproduce the hand-built PEM byte for byte.
			exp, err := k2.ExportPrivate("rfc", pass)
			if err != nil {
				t.Fatal(err)
			}
			gotPEM, err := keystore.MarshalPrivateKeyPEM(exp)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotPEM, privPEM) {
				t.Fatalf("exported PEM differs from the hand-built PKCS#8:\n%s\nwant\n%s", gotPEM, privPEM)
			}
			wantPubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spkiFromPub(pub)})
			gotPubPEM, err := keystore.MarshalPublicKeyPEM(ed25519.PublicKey(pub))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotPubPEM, wantPubPEM) {
				t.Fatalf("public PEM differs from the hand-built SPKI:\n%s\nwant\n%s", gotPubPEM, wantPubPEM)
			}
			back, err := keystore.ParsePublicKeyPEM(gotPubPEM)
			if err != nil || !bytes.Equal(back, pub) {
				t.Fatalf("public PEM round trip: %x, %v", back, err)
			}

			// A wrong passphrase never yields a signer.
			if _, err := k2.Signer("rfc", []byte("rfc 8032 passphrasE")); err == nil {
				t.Fatal("wrong passphrase unlocked the key")
			}
		})
	}
}

// TestKATFingerprint: Fingerprint is "SHA256:" + unpadded standard base64 of SHA-256 over
// the SPKI DER. Checked for every RFC key against an independent recomputation, and for
// RFC TEST 1 against a value produced by OpenSSL 3.5.9 (Alpine, Apple `container`,
// 2026-10-19):
//
//	printf '302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a' \
//	  | (hex to binary) | openssl pkey -pubin -inform DER -outform DER \
//	  | openssl dgst -sha256 -binary | openssl base64 -A
//	=> BuP9j9opu2CrWVV95h7bCuzbIxE0vjDnW0Vfjht5L6k=   (the code drops the "=" padding)
func TestKATFingerprint(t *testing.T) {
	const opensslTest1 = "SHA256:BuP9j9opu2CrWVV95h7bCuzbIxE0vjDnW0Vfjht5L6k"
	for i, v := range rfc8032Vectors {
		pub := unhex(t, v.pub)
		sum := sha256.Sum256(spkiFromPub(pub))
		want := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
		got := keystore.Fingerprint(ed25519.PublicKey(pub))
		if got != want {
			t.Errorf("%s: Fingerprint = %s, independent recomputation %s", v.name, got, want)
		}
		if i == 0 && got != opensslTest1 {
			t.Errorf("%s: Fingerprint = %s, OpenSSL %s", v.name, got, opensslTest1)
		}
		if len(got) != len("SHA256:")+43 || got[len(got)-1] == '=' {
			t.Errorf("%s: %q is not SHA256: plus 43 unpadded base64 characters", v.name, got)
		}
	}
}

// TestKATWrittenKDFParams: what a writer stamps into the file is the documented
// production cost (docs/format.md "Encryption": 64 MiB, t=3, p=1, 16-byte salt, argon2id).
// TestMain lowers kdf.Default for speed, so it is set to the shipped values here and the
// written JSON is read back raw, not through the library.
func TestKATWrittenKDFParams(t *testing.T) {
	prod := kdf.Default
	kdf.Default = kdf.Cost{Mem: 64 * 1024, Time: 3, Par: 1}
	defer func() { kdf.Default = prod }()

	path := filepath.Join(t.TempDir(), "r.ks")
	k, err := keystore.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(unhex(t, rfc8032Vectors[0].seed))
	if err := k.Import("k", priv, []byte("kat passphrase")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Entries []struct {
			KDF struct {
				Algo string
				Mem  uint32
				Time uint32
				Par  uint8
				Salt []byte
			} `json:"kdf"`
			Nonce []byte
		}
	}
	if err := json.Unmarshal(b, &f); err != nil || len(f.Entries) != 1 {
		t.Fatalf("written ring: %v, %d entries\n%s", err, len(f.Entries), b)
	}
	e := f.Entries[0]
	if e.KDF.Algo != "argon2id" || e.KDF.Mem != 65536 || e.KDF.Time != 3 || e.KDF.Par != 1 || len(e.KDF.Salt) != 16 || len(e.Nonce) != 12 {
		t.Fatalf("written kdf/nonce = %+v, nonce %d bytes; want argon2id 65536/3/1, 16-byte salt, 12-byte nonce", e.KDF, len(e.Nonce))
	}
}
