package sphinx

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
)

const routeBlindingHMACKey = "blinded_node_id"

// BlindedPath represents all the data that the creator of a blinded path must
// transmit to the builder of route that will send to this path.
type BlindedPath struct {
	// IntroductionPoint is the real node ID of the first hop in the blinded
	// path. The sender should be able to find this node in the network
	// graph and route to it.
	IntroductionPoint *btcec.PublicKey

	// BlindingPoint is the first ephemeral blinding point. This is the
	// point that the introduction node will use in order to create a shared
	// secret with the builder of the blinded route. This point will need
	// to be communicated to the introduction node by the sender in some
	// way.
	BlindingPoint *btcec.PublicKey

	// BlindedHops is a list of ordered BlindedHopInfo. Each entry
	// represents a hop in the blinded path along with the encrypted data to
	// be sent to that node. Note that the first entry in the list
	// represents the introduction point of the path and so the node ID of
	// this point does not strictly need to be transmitted to the sender
	// since they will be able to derive the point using the BlindingPoint.
	BlindedHops []*BlindedHopInfo
}

// hopInfo represents a single hop in a blinded path. The BlindedHopInfo wrapper
// of this type should be used when the members of the struct represent the real
// node pub key and clear text payload. The UnBlindedHopInfo wrapper should be
// used when the blinded node pub key and payload are being used.
type hopInfo struct {
	// NodePub is the public key of the hop. It represents the real pub key
	// if the UnBlindedHopInfo wrapper is used and represents the blinded
	// pub key if the BlindedHopInfo wrapper is used.
	NodePub *btcec.PublicKey

	// Payload is the data to be transported to the hop. It is the cleartext
	// if the UnBlindedHopInfo wrapper is used and is the ciphertext if the
	// BlindedHopInfo wrapper is used.
	Payload []byte
}

// BlindedHopInfo represents a blinded node pub key along with the blinded data
// for that node.
type BlindedHopInfo hopInfo

// UnBlindedHopInfo represents a real node pub key along with the plaintext data
// for that node.
type UnBlindedHopInfo hopInfo

// BuildBlindedPath creates a new BlindedPath from a list of UnBlindedHopInfo
// and a session key.
func BuildBlindedPath(sessionKey *btcec.PrivateKey,
	paymentPath []*UnBlindedHopInfo) (*BlindedPath, error) {

	if len(paymentPath) < 1 {
		return nil, fmt.Errorf("at least 1 hop is required to create " +
			"a blinded path")
	}

	bp := BlindedPath{
		IntroductionPoint: paymentPath[0].NodePub,
		BlindingPoint:     sessionKey.PubKey(),
		BlindedHops:       make([]*BlindedHopInfo, len(paymentPath)),
	}

	keys := make([]*btcec.PublicKey, len(paymentPath))
	for i, p := range paymentPath {
		keys[i] = p.NodePub
	}

	hopSharedSecrets, err := generateSharedSecrets(keys, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("error generating shared secret: %v",
			err)
	}

	for i, hop := range paymentPath {
		blindedInfo, err := BlindHopInfo(hop, hopSharedSecrets[i])
		if err != nil {
			return nil, err
		}

		bp.BlindedHops[i] = blindedInfo
	}

	return &bp, nil
}

// BlindHopInfo uses the given sharedSecret to blind the UnBlindedHopInfo and
// returns the associated BlindedHopInfo.
func BlindHopInfo(info *UnBlindedHopInfo, sharedSecret Hash256) (
	*BlindedHopInfo, error) {

	blindedData, err := BlindData(sharedSecret, info.Payload)
	if err != nil {
		return nil, err
	}

	blindedNodeKey := BlindNodeID(sharedSecret, info.NodePub)

	return &BlindedHopInfo{
		NodePub: blindedNodeKey,
		Payload: blindedData,
	}, nil
}

// BlindNodeID blinds the given public key using the provided shared secret.
func BlindNodeID(sharedSecret Hash256,
	pubKey *btcec.PublicKey) *btcec.PublicKey {

	blindingFactorBytes := generateKey(routeBlindingHMACKey, &sharedSecret)

	var blindingFactor btcec.ModNScalar
	blindingFactor.SetBytes(&blindingFactorBytes)

	return blindGroupElement(pubKey, blindingFactor)
}

// BlindData blinds/encrypts the given plain text data using the provided
// shared secret.
func BlindData(sharedSecret Hash256, plainTxt []byte) ([]byte, error) {
	rho := generateKey("rho", &sharedSecret)
	enc, err := chacha20polyEncrypt(rho[:], plainTxt)
	if err != nil {
		return nil, err
	}

	return enc, nil
}

// DecryptBlindedData decrypts the data encrypted by the creator of the blinded
// route.
func DecryptBlindedData(privKey SingleKeyECDH, ephemPub *btcec.PublicKey,
	encryptedData []byte) ([]byte, error) {

	ss, err := privKey.ECDH(ephemPub)
	if err != nil {
		return nil, err
	}

	ssHash := Hash256(ss)
	rho := generateKey("rho", &ssHash)
	return chacha20polyDecrypt(rho[:], encryptedData)
}

// NextEphemeral computes the next ephemeral key given the current ephemeral
// key and this node's private key.
func (r *Router) NextEphemeral(ephemPub *btcec.PublicKey) (*btcec.PublicKey,
	error) {

	ss, err := r.onionKey.ECDH(ephemPub)
	if err != nil {
		return nil, err
	}

	blindingFactor := computeBlindingFactor(ephemPub, ss[:])
	nextEphem := blindGroupElement(ephemPub, blindingFactor)

	return nextEphem, nil
}
