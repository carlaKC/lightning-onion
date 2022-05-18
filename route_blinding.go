package sphinx

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Blinded routes use a 12 byte zero nonce.
var blindingNonce = [12]byte{}

// IntroductionNode contains the data required for an introduction node in a
// blinded route. This node is a special case along the route because its node
// id is not encrypted, and it is provided with _both_ the ephemeral key and
// encrypted blob to start the route off.
type IntroductionNode struct {
	// Pubkey is the node's (unblinded) public key that identifies it on
	// the network.
	Pubkey *btcec.PublicKey

	// EncryptedData is a blob of data provided to the introduction node to
	// point it to the next node along the route.
	EncryptedData []byte

	// EphemeralKey is the key used to decrypt the encrypted data blob
	// (with knowledge of the node's private key) to find the next node
	// along the blinded route.
	EphemeralKey *btcec.PublicKey
}

// BlindedHop contains the pubkey and encrypted data blob for a hop along a
// blinded route.
type BlindedHop struct {
	// BlindedPubkey is the blinded public key for a hop.
	BlindedPubkey *btcec.PublicKey

	// EncryptedData is a blob of encrypted data containing a payload for
	// the blinded node.
	EncryptedData []byte
}

// BlindedRoute contains the introduction point and blinded hops that make up
// a blinded route.
type BlindedRoute struct {
	// Introduction is the first, unblinded node in the route.
	IntroductionNode *IntroductionNode

	// Hops is an ordered set of hops from the introduction node to the
	// destination (possibly containing dummy hops).
	//
	// A blinded route is has the following order:
	// IntroductionNode -> Hops[0] -> ... -> Hops[n].
	Hops []*BlindedHop
}

// CreateBlindedRoute creates a set of encrypted blobs to represent a blinded
// route. The public keys and payloads provided represent the nodes (and data
// they require) from introduction node -> destination.
func CreateBlindedRoute(route []*btcec.PublicKey, payloads [][]byte,
	sessionKey *btcec.PrivateKey) (*BlindedRoute, error) {

	if len(route) < 1 {
		return nil, fmt.Errorf("Blinded route requires at least 2 "+
			"hops got: %v", len(route))
	}

	if len(route) != len(payloads) {
		return nil, fmt.Errorf("Blinded route requires same number "+
			"of hops (%v) and payloads (%v)", len(route),
			len(payloads))
	}

	secrets, err := generateSharedSecrets(route, sessionKey)
	if err != nil {
		return nil, err
	}

	// TODO: pad payloads to length of longest payload.
	introHopData, err := encryptHopData(&secrets[0], payloads[0])
	if err != nil {
		return nil, err
	}

	blindedRoute := &BlindedRoute{
		IntroductionNode: &IntroductionNode{
			Pubkey:        route[0],
			EncryptedData: introHopData,
			EphemeralKey:  sessionKey.PubKey(),
		},
		Hops: make([]*BlindedHop, len(route)-1),
	}

	for i := 1; i < len(route); i++ {
		nodeID := generateBlindedNodeID(route[i], secrets[i])

		dataBlob, err := encryptHopData(&secrets[i], payloads[i])
		if err != nil {
			return nil, err
		}

		// Decrement i by 1 because we've cut our introduction node
		// off from the route.
		blindedRoute.Hops[i-1] = &BlindedHop{
			BlindedPubkey: nodeID,
			EncryptedData: dataBlob,
		}
	}

	return blindedRoute, nil
}

// HMAC256("blinded_node_id", ss(i)) * N(i)
func generateBlindedNodeID(node *btcec.PublicKey,
	sharedSecret Hash256) *btcec.PublicKey {

	// blindingFactor = HMAC256("blinded_node_id", ss(i))
	blindingFactor := generateKey("blinded_node_id", &sharedSecret)

	var blindingBytes btcec.ModNScalar
	blindingBytes.SetByteSlice(blindingFactor[:])

	return blindGroupElement(node, blindingBytes)
}

// encryptHopData encrypts the payload provided using the
func encryptHopData(sharedSecret *Hash256, payload []byte) ([]byte, error) {
	rhoKey := generateKey("rho", sharedSecret)

	cipher, err := chacha20poly1305.New(rhoKey[:])
	if err != nil {
		return nil, err
	}

	return cipher.Seal(payload[:0], blindingNonce[:], payload, nil), nil
}
