package sphinx

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

const (
	bobSessionKeyStr = "0202020202020202020202020202020202020202020202020202020202020202"

	bobNodeIDStr = "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c"

	bobPrivkeyStr = "4242424242424242424242424242424242424242424242424242424242424242"

	bobTLVStr = "0110000000000000000000000000000000000208000000000000002a0421027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007fdfde903123456"

	bobEphPrivStr = "0202020202020202020202020202020202020202020202020202020202020202"

	bobEphPubStr = "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766"

	carolNodeIDStr = "027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007"

	carolTLVs = "0421032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e6686809910821031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"

	// The following constants are used to test our results, they may have
	// some duplication with the values we use as input, but are kept
	// separate to ensure we don't accidentally test buggy input about
	// buggy output.
	bobIntroNodeStr = "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c"

	bobEncDataStr = "cd4b00ff9c09ed28102b210ac73aa12d63e90a5acebc496c49f57c639e098acbaec5b5ffb8592b07bdb6665ccb56f1258ab1857383f6542c8371dcee568a0a35a218288814849db13ce6f84a464fa517d9e1684333e3"

	carolBlindedIDStr = "02e466727716f044290abf91a14a6d90e87487da160c2a3cbd0d465d7a78eb83a7"

	carolEncDataStr = "ca26157e44ab01e82becf86497e1d05ad3e70903d22721210af41d791bf406873024d95b7a1ad128b2526932febfeeab237000563c1f33c78530b3880f8407326eef8bc004932b22323d13343ef740019c08e538e5c5"
)

// TestCreateBlindedRoute tests the creation of a blinded route using the
// test vectors provided by the specification.
func TestCreateBlindedRoute(t *testing.T) {
	sessionPrivKeyBytes, err := hex.DecodeString(bobSessionKeyStr)
	require.NoError(t, err, "session hex decode")

	sessionPrivkey, _ := btcec.PrivKeyFromBytes(sessionPrivKeyBytes)

	bobPubkeyBytes, err := hex.DecodeString(bobNodeIDStr)
	require.NoError(t, err, "bob hex decode")

	bobPubkey, err := btcec.ParsePubKey(bobPubkeyBytes)
	require.NoError(t, err, "bob pubkey")

	bobPayload, err := hex.DecodeString(bobTLVStr)
	require.NoError(t, err, "bob TLVs")

	// bobEphemeralPrivBytes, err := hex.DecodeString(bobEphPrivStr)
	// require.NoError(t, err, "bob ephemeral priv hex")

	bobEmphemeralPubBytes, err := hex.DecodeString(bobEphPubStr)
	require.NoError(t, err, "bob ephemeral pub hex")

	bobEphemeralPubKey, err := btcec.ParsePubKey(bobEmphemeralPubBytes)
	require.NoError(t, err, "bob ephemeral pub")

	carolPubkeyBytes, err := hex.DecodeString(carolNodeIDStr)
	require.NoError(t, err, "carol hex decode")

	carolPubkey, err := btcec.ParsePubKey(carolPubkeyBytes)
	require.NoError(t, err, "carol pubkey")

	carolPayload, err := hex.DecodeString(carolTLVs)
	require.NoError(t, err, "carol TLVs")

	// Parse results
	introductionNodeBytes, err := hex.DecodeString(bobIntroNodeStr)
	require.NoError(t, err, "introduction hex")

	introductionNodePubkey, err := btcec.ParsePubKey(introductionNodeBytes)
	require.NoError(t, err, "introduction pubkey")

	bobEncryptedDataBytes, err := hex.DecodeString(bobEncDataStr)
	require.NoError(t, err, "bob encrypted data")

	carolBlindedIDBytes, err := hex.DecodeString(carolBlindedIDStr)
	require.NoError(t, err, "carol blinded hex")

	carolBlindedPubkey, err := btcec.ParsePubKey(carolBlindedIDBytes)
	require.NoError(t, err, "carol blinded pubkey")

	carolEncryptedDataBytes, err := hex.DecodeString(carolEncDataStr)
	require.NoError(t, err)

	tests := []struct {
		name          string
		route         []*btcec.PublicKey
		payloads      [][]byte
		sessionKey    *btcec.PrivateKey
		expectedRoute *BlindedRoute
	}{
		{
			name: "bob creates a bob -> carol route",
			route: []*btcec.PublicKey{
				bobPubkey, carolPubkey,
			},
			payloads: [][]byte{
				bobPayload, carolPayload,
			},
			sessionKey: sessionPrivkey,
			expectedRoute: &BlindedRoute{
				IntroductionNode: &IntroductionNode{
					Pubkey:        introductionNodePubkey,
					EncryptedData: bobEncryptedDataBytes,
					EphemeralKey:  bobEphemeralPubKey,
				},
				Hops: []*BlindedHop{
					{
						BlindedPubkey: carolBlindedPubkey,
						EncryptedData: carolEncryptedDataBytes,
					},
				},
			},
		},
	}

	for _, testCase := range tests {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			testBlindedIDAndPayload(
				t, testCase.route, testCase.payloads,
				testCase.sessionKey, testCase.expectedRoute,
			)
		})
	}
}

func testBlindedIDAndPayload(t *testing.T, route []*btcec.PublicKey,
	payloads [][]byte, sessionKey *btcec.PrivateKey,
	expectedRoute *BlindedRoute) {

	blindedRoute, err := CreateBlindedRoute(
		route, payloads, sessionKey,
	)
	require.NoError(t, err, "create blinded route failed")

	// Although we can require that the full route is equal, breaking down
	// to components makes debugging easier.
	require.Equal(t, expectedRoute.IntroductionNode,
		blindedRoute.IntroductionNode, "introduction node")

	for i, _ := range expectedRoute.Hops {
		require.Equal(t, expectedRoute.Hops[i], blindedRoute.Hops[i],
			fmt.Sprintf("hop: %v", i))
	}
}

// TestDecryptBlindedRoute tests decryption of encoded data blobs provided in
// blinded routes, and calculation of the next ephemeral pubkey to be passed to
// the next node in the blinded route.
func TestDecryptBlindedRoute(t *testing.T) {
	bobPrivKeyBytes, err := hex.DecodeString(bobPrivkeyStr)
	require.NoError(t, err, "bob priv hex")

	bobPrivKey, _ := btcec.PrivKeyFromBytes(bobPrivKeyBytes)

	bobEmphemeralPubBytes, err := hex.DecodeString(bobEphPubStr)
	require.NoError(t, err, "bob ephemeral pub hex")

	bobEphemeralPubKey, err := btcec.ParsePubKey(bobEmphemeralPubBytes)
	require.NoError(t, err, "bob ephemeral pub")

	bobEncryptedDataBytes, err := hex.DecodeString(bobEncDataStr)
	require.NoError(t, err, "bob encrypted data")

	bobPayload, err := hex.DecodeString(bobTLVStr)
	require.NoError(t, err, "bob TLVs")

	tests := []struct {
		name          string
		nodeKey       *btcec.PrivateKey
		ephemeralKey  *btcec.PublicKey
		encryptedData []byte

		expectedData     []byte
		nextEphemeralKey *btcec.PublicKey
	}{
		{
			name:          "bob decrypt tlvs, get carol's next pubkey",
			nodeKey:       bobPrivKey,
			ephemeralKey:  bobEphemeralPubKey,
			encryptedData: bobEncryptedDataBytes,

			expectedData: bobPayload,
			// TODO - carla: derive next ephemeral pubkey
		},
	}

	for _, testCase := range tests {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			testDecryptBlindedRoute(
				t, testCase.nodeKey, testCase.ephemeralKey,
				testCase.encryptedData, testCase.expectedData,
			)
		})
	}
}

func testDecryptBlindedRoute(t *testing.T, privkey *btcec.PrivateKey,
	ephemeralKey *btcec.PublicKey, payload, expected []byte) {

	privkeyECDH := &PrivKeyECDH{
		PrivKey: privkey,
	}

	decrypted, err := decryptHopData(privkeyECDH, ephemeralKey, payload)
	require.NoError(t, err, "decrypt failed")
	require.Equal(t, expected, decrypted, "payload wrong")
}
