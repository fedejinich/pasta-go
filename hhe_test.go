package pasta

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"math/rand"
	"testing"
)

var P = Params{SecretKeySize, PlaintextSize, CiphertextSize, 3}

//func TestPackedUseCase(t *testing.T) {
//	secretKey := []uint64{0x892f9ff42160c81, 0xa652a61d10eabf3, 0x76bb71c0ddc0c06,
//		0xcd4219dc5300904, 0xb555b02f174ea12, 0xaf3a4ea03c081fd,
//		0x2e5ca6dc0c3122a, 0x73c7bb66bee9643, 0x68568756417a3da,
//		0x50be80234874982, 0xbfb0b39827ac73f, 0x8d81bf84a35fec7,
//		0x4c6a515ad3a342e, 0x9222548d6f505bc, 0x154aaa9108d72c9,
//		0x5f700f7a2966f4b, 0x51311bfe5e66132, 0xbb1f2488cf388c0,
//		0x8923ef9749307f6, 0xc7db00ff85a54c8, 0x45c55a0e561ad54,
//		0x0877e89ed848c7d, 0xe584219f06e1eb5, 0xc0207fbdd155b36,
//		0x030e34be1a4916b, 0x5ea2bb5315bb2bc, 0xe242363b8e1888a,
//		0xd7cd0f83dc0dbbe, 0x1d6f84a7b4f4ae4, 0x3f572774465aac8,
//		0x90790b1397e0a14, 0xb34152fe0115879, 0x60b375ae8930c86,
//		0x520a8f29a0e8567, 0x6c4ceb278c114c6, 0x34eaea9efbdf10f,
//		0xb1d7966e4910f74, 0xb195568e073dab7, 0x39a3a71300f1c89,
//		0xc4a1d459b36054a, 0x9ebb00461b68a1e, 0x52c241416d61c2e,
//		0xdbcd53c45e512ac, 0xb1625548afe46b4, 0x5cf6e8c1c793d21,
//		0xa751b931643bc4a, 0x0cb6456cd70e1da, 0x22ab9c2a8f6b474,
//		0xc8720c70727857e, 0x01a26e8335b163d, 0x5285f3756f7ca23,
//		0xca030eaced23066, 0x672c2341285025c, 0x18afc3094439aa9,
//		0xb680c3d84f433df, 0x1d0ea68d581425b, 0x1cd09c42097117d,
//		0x4972fd77469456b, 0xd0d2d16f84bf039, 0x29faba1e7672a70,
//		0x5ee86e47992871d, 0x843f42d30f2ce13, 0xdb6c1f645aa71c5,
//		0x0b84a30ca6f401a, 0xcf8ead679390b25, 0x3ccf618a1b34f0a,
//		0x3fb998a3a37b84b, 0xdffec72a0ab2639, 0x4ad39327f6c0a65,
//		0x49543a3664dd857, 0x67c25732b78afab, 0x1cd2a253b3bb7b3,
//		0x27891dd76663467, 0x7d354f76cf4fc50, 0x7259c10ee043014,
//		0x36129cd1207f768, 0xb955bca043edba9, 0x701a70021a444f9,
//		0x9976f1c430465d5, 0xe797036fa297ae0, 0x19a5be62daf7d09,
//		0x438d6de681867ef, 0xf0d9aeb988204b0, 0x7ce71a27efad452,
//		0xefce163ea1d8d56, 0x6dddb1eaa71d598, 0x62cb3ae78950bec,
//		0x27d9c87ba64b8de, 0x72d1f27d152ba7e, 0x78ddd82f940453a,
//		0x4b34224491ce139, 0x34341198b57d1f7, 0xb0baeb6d1a3e6d2,
//		0x00ebaf5410a2a9e, 0x121dfcbcd9bd6e2, 0xb60a082f03335c8,
//		0xe1c85a817ab86d2, 0x9d8ed73030d7e5a, 0x38ac9243b56bfe9,
//		0x141f04b1352ab52, 0x3b22818d71d517f, 0x0564454c4a88f08,
//		0x9d18d9ab1fbbd4a, 0xa9416b810831904, 0x38cc60cb2e1161f,
//		0xae39dad01be4c3f, 0x54f8038061b2abf, 0x9166a28c4368060,
//		0x3b899af28a38de5, 0xf09acc8187a56a3, 0x013247429f9f51b,
//		0x9adc5fffa69cac4, 0x225652bec6814fe, 0xdaa1b7bd32c5d60,
//		0x27886e98288979b, 0x22ad1d2ad81f092, 0xb7067c0d6d64276,
//		0x7629dd7467cad88, 0x8d3072e79305da6, 0x624ba51a417c389,
//		0x1dcbc3e9eebd85e, 0xc114e4a3a0b644a, 0x6ee23e3cc2cf3f0,
//		0xc95e3d69369adec, 0x575ef94e2d8956e, 0x0fb4a1f911f767d,
//		0x1df5762dd7b3571, 0x9302b150ad67d44, 0xe3bda67ec878d67,
//		0x62d9162332f4c4e, 0x4cce39ee3b6f9e8, 0xc9a21fd7014acda,
//		0xef542d33f0361dd, 0xf1158666c84e5f6, 0xc2418a64ce1b871,
//		0x1a3718ef0432943, 0x1acce3416d31b67, 0x978644123e266ed,
//		0x60d0190bb4eb08a, 0xd7b18102dd6534e, 0xea17c999a91103e,
//		0x9d9ae729c8c36cc, 0x34349a44ba7ac9e, 0x19690130559b11e,
//		0x287aa1c5640fe38, 0xcb9ee5a34d2646d, 0xc72bcff34b0aef0,
//		0x9d554b0c0b8d18c, 0x328ee2e69613bbc, 0xa4e07818eeac88d,
//		0x5c4950afa7dbc07, 0x1339bd35b8b8454, 0x8cf7b2cadfcaea1,
//		0xbe519bc3ec42453, 0x2408d2795492507, 0xaa110bbb31e085e,
//		0x09d0ac1a6884279, 0x25a02dfbcda8780, 0x74f63e314bd5e0b,
//		0xcddd7cc1782d0fe, 0x1ec6882ecd2535d, 0x4a6f5d484455cc3,
//		0x90bf56cab3867e3, 0x3a521bd770d30f1, 0x381b110169f908d,
//		0xb55c79924ef72fd, 0x817bf65abab94a1, 0x6c877a9219ee4ae,
//		0x76221d19899227f, 0xa3a38fe6bb8cb5c, 0x794ce42499fd9a4,
//		0x56a17de221d3832, 0x0f36eeb67e50936, 0x0d4ce7bd40fd3f6,
//		0x57d7c284663cff1, 0x1e1e800e2fe3f81, 0x3258220f24ccd1f,
//		0xaf9dd2eaacc8480, 0x34183dad9f3ca6b, 0x28dbf02c1fec25d,
//		0xdd52a11f5859ecc, 0x1ce3e8ce1649ca4, 0x11c88d7e76c1812,
//		0x1a0344b98cee2f1, 0x8447c6cec074196, 0x520c99c978e1a2c,
//		0x9713baf1ce504f3, 0x79b9c17a7169b03, 0xa20c78cb2508455,
//		0x4d603a63fe48869, 0x5649e649dd1d078, 0xd6b4c6e1a9afb05,
//		0x84c93eac4b8af66, 0x8a193c985be64d4, 0x9d00473749d7c36,
//		0xc7f02e7d4c5940b, 0x2298c824123f55e, 0xe4ef5e2906d1f42,
//		0xe6e3ac3876ba2ff, 0xd478fae309cd261, 0x61d62f5431f50ba,
//		0xda636d7a1c7820b, 0xea4f0fe4b27a917, 0xbd3bffe9da412c0,
//		0x48865cf01ac0dc9, 0xc3c99592768b8c0, 0xa3b01c41f9759ab,
//		0xc90aeccd913b72d, 0x34bbc662576af4c, 0xd8c603e3f452af4,
//		0xc7ccd33c7ec8840, 0x1dd72b9a940203b, 0x5332de587ef6db7,
//		0x921f0a7f394da31, 0x788b7b11db2eb65, 0x8657d7524e65147,
//		0x75e1c8d5bfc9a3b, 0x30fa1c4cf4d3b6d, 0x43db33e721dfe80,
//		0xd7a699cb891b5d6, 0xb33ad679478ad3e, 0x4847ab80b7a21fa,
//		0x99aabdd4c393f0a, 0xa3a7989d84dc62b, 0x86d459c88ebad93,
//		0xd9d55537bd0f974, 0x543feeb02e0bd9f, 0x918e8b9e5f54d4d,
//		0x37fafcb12037f70, 0x0ed21ba0e71b793, 0xb741c4301534f0b,
//		0x4c66b270793f7f9, 0x5609871e35ce1fa, 0x4432dc43bf512ec,
//		0x8858a0bf0a8c024, 0x184d0fbcc20130e, 0xce1f9c7ca1852e3,
//		0xc0812d8e0e957a7, 0x5b2943c2e5b21d3, 0x8e532357645eaeb,
//		0xb5ea9dff9aab02b, 0xe58050315f1308c, 0x4285f91e3fdbfbd,
//		0x9826404c7c75a7d, 0x71a5270243bacd8, 0x5bf863318fe3897,
//		0xee07f435bb94402, 0x07e5db3cd0a5058, 0x8fabbb695ce4e58,
//		0x749b40188817a03, 0x16b02668d56a1e8, 0xab13d13e5bda090,
//		0x183c5893ffc193b, 0xe912d72bb7f9e53, 0xa861731333ecb85,
//		0xca48bde9146c726}
//	plainMod := 1096486890805657601
//	modDegree := 65536
//	secLevel := 128
//	matrixSize := 200
//
//	packedTest(t, secretKey, uint64(plainMod), uint64(modDegree), uint64(secLevel), uint64(matrixSize))
//}

func TestPackedUseCase(t *testing.T) {
	secretKey := []uint64{0x892f9ff42160c81, 0xa652a61d10eabf3, 0x76bb71c0ddc0c06,
		0xcd4219dc5300904, 0xb555b02f174ea12, 0xaf3a4ea03c081fd,
		0x2e5ca6dc0c3122a, 0x73c7bb66bee9643, 0x68568756417a3da,
		0x50be80234874982, 0xbfb0b39827ac73f, 0x8d81bf84a35fec7,
		0x4c6a515ad3a342e, 0x9222548d6f505bc, 0x154aaa9108d72c9,
		0x5f700f7a2966f4b, 0x51311bfe5e66132, 0xbb1f2488cf388c0,
		0x8923ef9749307f6, 0xc7db00ff85a54c8, 0x45c55a0e561ad54,
		0x0877e89ed848c7d, 0xe584219f06e1eb5, 0xc0207fbdd155b36,
		0x030e34be1a4916b, 0x5ea2bb5315bb2bc, 0xe242363b8e1888a,
		0xd7cd0f83dc0dbbe, 0x1d6f84a7b4f4ae4, 0x3f572774465aac8,
		0x90790b1397e0a14, 0xb34152fe0115879, 0x60b375ae8930c86,
		0x520a8f29a0e8567, 0x6c4ceb278c114c6, 0x34eaea9efbdf10f,
		0xb1d7966e4910f74, 0xb195568e073dab7, 0x39a3a71300f1c89,
		0xc4a1d459b36054a, 0x9ebb00461b68a1e, 0x52c241416d61c2e,
		0xdbcd53c45e512ac, 0xb1625548afe46b4, 0x5cf6e8c1c793d21,
		0xa751b931643bc4a, 0x0cb6456cd70e1da, 0x22ab9c2a8f6b474,
		0xc8720c70727857e, 0x01a26e8335b163d, 0x5285f3756f7ca23,
		0xca030eaced23066, 0x672c2341285025c, 0x18afc3094439aa9,
		0xb680c3d84f433df, 0x1d0ea68d581425b, 0x1cd09c42097117d,
		0x4972fd77469456b, 0xd0d2d16f84bf039, 0x29faba1e7672a70,
		0x5ee86e47992871d, 0x843f42d30f2ce13, 0xdb6c1f645aa71c5,
		0x0b84a30ca6f401a, 0xcf8ead679390b25, 0x3ccf618a1b34f0a,
		0x3fb998a3a37b84b, 0xdffec72a0ab2639, 0x4ad39327f6c0a65,
		0x49543a3664dd857, 0x67c25732b78afab, 0x1cd2a253b3bb7b3,
		0x27891dd76663467, 0x7d354f76cf4fc50, 0x7259c10ee043014,
		0x36129cd1207f768, 0xb955bca043edba9, 0x701a70021a444f9,
		0x9976f1c430465d5, 0xe797036fa297ae0, 0x19a5be62daf7d09,
		0x438d6de681867ef, 0xf0d9aeb988204b0, 0x7ce71a27efad452,
		0xefce163ea1d8d56, 0x6dddb1eaa71d598, 0x62cb3ae78950bec,
		0x27d9c87ba64b8de, 0x72d1f27d152ba7e, 0x78ddd82f940453a,
		0x4b34224491ce139, 0x34341198b57d1f7, 0xb0baeb6d1a3e6d2,
		0x00ebaf5410a2a9e, 0x121dfcbcd9bd6e2, 0xb60a082f03335c8,
		0xe1c85a817ab86d2, 0x9d8ed73030d7e5a, 0x38ac9243b56bfe9,
		0x141f04b1352ab52, 0x3b22818d71d517f, 0x0564454c4a88f08,
		0x9d18d9ab1fbbd4a, 0xa9416b810831904, 0x38cc60cb2e1161f,
		0xae39dad01be4c3f, 0x54f8038061b2abf, 0x9166a28c4368060,
		0x3b899af28a38de5, 0xf09acc8187a56a3, 0x013247429f9f51b,
		0x9adc5fffa69cac4, 0x225652bec6814fe, 0xdaa1b7bd32c5d60,
		0x27886e98288979b, 0x22ad1d2ad81f092, 0xb7067c0d6d64276,
		0x7629dd7467cad88, 0x8d3072e79305da6, 0x624ba51a417c389,
		0x1dcbc3e9eebd85e, 0xc114e4a3a0b644a, 0x6ee23e3cc2cf3f0,
		0xc95e3d69369adec, 0x575ef94e2d8956e, 0x0fb4a1f911f767d,
		0x1df5762dd7b3571, 0x9302b150ad67d44, 0xe3bda67ec878d67,
		0x62d9162332f4c4e, 0x4cce39ee3b6f9e8, 0xc9a21fd7014acda,
		0xef542d33f0361dd, 0xf1158666c84e5f6, 0xc2418a64ce1b871,
		0x1a3718ef0432943, 0x1acce3416d31b67, 0x978644123e266ed,
		0x60d0190bb4eb08a, 0xd7b18102dd6534e, 0xea17c999a91103e,
		0x9d9ae729c8c36cc, 0x34349a44ba7ac9e, 0x19690130559b11e,
		0x287aa1c5640fe38, 0xcb9ee5a34d2646d, 0xc72bcff34b0aef0,
		0x9d554b0c0b8d18c, 0x328ee2e69613bbc, 0xa4e07818eeac88d,
		0x5c4950afa7dbc07, 0x1339bd35b8b8454, 0x8cf7b2cadfcaea1,
		0xbe519bc3ec42453, 0x2408d2795492507, 0xaa110bbb31e085e,
		0x09d0ac1a6884279, 0x25a02dfbcda8780, 0x74f63e314bd5e0b,
		0xcddd7cc1782d0fe, 0x1ec6882ecd2535d, 0x4a6f5d484455cc3,
		0x90bf56cab3867e3, 0x3a521bd770d30f1, 0x381b110169f908d,
		0xb55c79924ef72fd, 0x817bf65abab94a1, 0x6c877a9219ee4ae,
		0x76221d19899227f, 0xa3a38fe6bb8cb5c, 0x794ce42499fd9a4,
		0x56a17de221d3832, 0x0f36eeb67e50936, 0x0d4ce7bd40fd3f6,
		0x57d7c284663cff1, 0x1e1e800e2fe3f81, 0x3258220f24ccd1f,
		0xaf9dd2eaacc8480, 0x34183dad9f3ca6b, 0x28dbf02c1fec25d,
		0xdd52a11f5859ecc, 0x1ce3e8ce1649ca4, 0x11c88d7e76c1812,
		0x1a0344b98cee2f1, 0x8447c6cec074196, 0x520c99c978e1a2c,
		0x9713baf1ce504f3, 0x79b9c17a7169b03, 0xa20c78cb2508455,
		0x4d603a63fe48869, 0x5649e649dd1d078, 0xd6b4c6e1a9afb05,
		0x84c93eac4b8af66, 0x8a193c985be64d4, 0x9d00473749d7c36,
		0xc7f02e7d4c5940b, 0x2298c824123f55e, 0xe4ef5e2906d1f42,
		0xe6e3ac3876ba2ff, 0xd478fae309cd261, 0x61d62f5431f50ba,
		0xda636d7a1c7820b, 0xea4f0fe4b27a917, 0xbd3bffe9da412c0,
		0x48865cf01ac0dc9, 0xc3c99592768b8c0, 0xa3b01c41f9759ab,
		0xc90aeccd913b72d, 0x34bbc662576af4c, 0xd8c603e3f452af4,
		0xc7ccd33c7ec8840, 0x1dd72b9a940203b, 0x5332de587ef6db7,
		0x921f0a7f394da31, 0x788b7b11db2eb65, 0x8657d7524e65147,
		0x75e1c8d5bfc9a3b, 0x30fa1c4cf4d3b6d, 0x43db33e721dfe80,
		0xd7a699cb891b5d6, 0xb33ad679478ad3e, 0x4847ab80b7a21fa,
		0x99aabdd4c393f0a, 0xa3a7989d84dc62b, 0x86d459c88ebad93,
		0xd9d55537bd0f974, 0x543feeb02e0bd9f, 0x918e8b9e5f54d4d,
		0x37fafcb12037f70, 0x0ed21ba0e71b793, 0xb741c4301534f0b,
		0x4c66b270793f7f9, 0x5609871e35ce1fa, 0x4432dc43bf512ec,
		0x8858a0bf0a8c024, 0x184d0fbcc20130e, 0xce1f9c7ca1852e3,
		0xc0812d8e0e957a7, 0x5b2943c2e5b21d3, 0x8e532357645eaeb,
		0xb5ea9dff9aab02b, 0xe58050315f1308c, 0x4285f91e3fdbfbd,
		0x9826404c7c75a7d, 0x71a5270243bacd8, 0x5bf863318fe3897,
		0xee07f435bb94402, 0x07e5db3cd0a5058, 0x8fabbb695ce4e58,
		0x749b40188817a03, 0x16b02668d56a1e8, 0xab13d13e5bda090,
		0x183c5893ffc193b, 0xe912d72bb7f9e53, 0xa861731333ecb85,
		0xca48bde9146c726}
	plainMod := 65537
	modDegree := 12
	secLevel := 128
	matrixSize := 200

	packedTest(t, secretKey, uint64(plainMod), uint64(modDegree), uint64(secLevel), uint64(matrixSize))
}

func packedTest(t *testing.T, secretKey []uint64, plainMod, modDegree, secLevel, matrixSize uint64) {
	fmt.Printf("Num matrices = %d\n", NumMatmulsSquares)
	fmt.Printf("N = %d\n", matrixSize)
	fmt.Print("Getting random elements...")

	// random matrices
	m := make([][][]uint64, NumMatmulsSquares)
	for r := 0; r < NumMatmulsSquares; r++ {
		m[r] = make([][]uint64, matrixSize)
		for i := 0; i < int(matrixSize); i++ {
			m[r][i] = make([]uint64, matrixSize)
			for j := 0; j < int(matrixSize); j++ {
				m[r][i][j] = rand.Uint64() % plainMod
			}
		}
	}

	// random biases
	b := make([][]uint64, NumMatmulsSquares)
	for r := 0; r < NumMatmulsSquares; r++ {
		b[r] = make([]uint64, matrixSize)
		for i := 0; i < int(matrixSize); i++ {
			b[r][i] = rand.Uint64() % plainMod
		}
	}

	// random input vector
	vi := make([]uint64, matrixSize)
	for i := 0; i < int(matrixSize); i++ {
		vi[i] = rand.Uint64() % plainMod
	}

	fmt.Println("Computing in plain...")

	// todo(fedejinich) implement this
	//for r := 0; r < NumMatmulsSquares; r++ {
	//	Affine()
	//	if !LastSquare && r != NumMatmulsSquares-1 {
	//		Square()
	//	}
	//}

	fmt.Println("...done")

	fmt.Println("Encrypting input...")

	pastaCipher := NewPasta(secretKey, plainMod, P)
	ciph := pastaCipher.Encrypt(vi)

	fmt.Println("... done")

	// todo(fedejinich) this will be refactored
	pastaParams := PastaParams{
		int(P.Rounds),
		int(P.CipherSize),
		int(plainMod),
	}
	// todo(fedejinich) this will be refactored
	sealParams := SealParams{
		// todo(fedejinich) hardcodeado hasta los huevos (pero de un caso de uso valido)
		4369324368,
		15021756563585537025,
	}
	bfvCipher, _, _, bfvEncoder, bfvParams := newBFVCipher(t, sealParams, pastaParams)

	ciphSec := bfvCipher.Encrypt(bfvEncoder.EncodeNew(secretKey, bfvParams.MaxLevel())) // todo(fedejinich) not sure about MaxLevel

	bfvCipher.Decomp(ciph, ciphSec)
}

func newBFVCipher(t *testing.T, sealParams SealParams, pastaParams PastaParams) (BFVCipher, rlwe.EvaluationKey,
	bfv.Evaluator, bfv.Encoder, bfv.Parameters) {

	//// BFV parameters (128 bit security) with plaintext modulus 1096486890805657601
	//params := bfv.ParametersLiteral{
	//	LogN: 65536,
	//	Q: []uint64{0xffffffffffc0001, 0xfffffffff840001, 0xfffffffff6a0001,
	//		0xfffffffff5a0001, 0xfffffffff2a0001, 0xfffffffff240001,
	//		0xffffffffefe0001, 0xffffffffeca0001, 0xffffffffe9e0001,
	//		0xffffffffe7c0001, 0xffffffffe740001, 0xffffffffe520001,
	//		0xffffffffe4c0001, 0xffffffffe440001, 0xffffffffe400001,
	//		0xffffffffdda0001, 0xffffffffdd20001, 0xffffffffdbc0001,
	//		0xffffffffdb60001, 0xffffffffd8a0001, 0xffffffffd840001,
	//		0xffffffffd6e0001, 0xffffffffd680001, 0xffffffffd2a0001,
	//		0xffffffffd000001, 0xffffffffcf00001, 0xffffffffcea0001,
	//		0xffffffffcdc0001, 0xffffffffcc40001}, // 1740 bits // coeff_modulus_ 1
	//	P: []uint64{},          // coeff_modulus_ 2
	//	T: 1096486890805657601, // mod_degree
	//}
	// BFV parameters (128 bit security) with plaintext modulus 1096486890805657601
	//paramDef := bfv.PN13QP218      // todo(fedejinich) choose a different set of parameters
	//paramDef.T = 0xF3781048B580001 // todo(fedejinich) '1096486890805657601', it should be a param
	//bfvParams, err := bfv.NewParametersFromLiteral(paramDef)
	//bfvParams, err := bfv.NewParametersFromLiteral(params)
	bfvParams, err := bfv.NewParametersFromLiteral(bfv.PN12QP101pq) // post-quantum params
	if err != nil {
		t.Errorf("couldn't initialize bfvParams")
	}
	kgen := bfv.NewKeyGenerator(bfvParams)
	secretKey, _ := kgen.GenKeyPair()
	evaluationKey := rlwe.EvaluationKey{}
	bfvEvaluator := bfv.NewEvaluator(bfvParams, evaluationKey) // todo(fedejinich) not sure about evaluation evaluationKey
	bfvEncoder := bfv.NewEncoder(bfvParams)
	bfv.NewDecryptor(bfvParams, secretKey)
	bfvCipher := NewBFVCipher(bfvParams, secretKey, sealParams, bfvEvaluator, bfvEncoder, pastaParams) // todo(fedejinich) can also be encrypted with the PK

	return bfvCipher, evaluationKey, bfvEvaluator, bfvEncoder, bfvParams
}
