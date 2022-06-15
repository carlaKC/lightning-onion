package sphinx

import "golang.org/x/crypto/chacha20poly1305"

// blindingNonce is the nonce used for encrypting data in a blinded route.
var blindingNonce = [12]byte{}

// BlobDecrypt is the signature of a function that can be used to decrypt
// the encrypted data that accompanies a blinded route.
type BlobDecrypt func([]byte) ([]byte, error)

func newBlobDecrypter(sharedSecret *Hash256) BlobDecrypt {
	return func(data []byte) ([]byte, error) {
		rhoKey := generateKey("rho", sharedSecret)

		cipher, err := chacha20poly1305.New(rhoKey[:])
		if err != nil {
			return nil, err
		}

		decrypted, err := cipher.Open(
			data[:0], blindingNonce[:], data, nil,
		)
		if err != nil {
			return nil, err
		}

		return decrypted, nil
	}
}
