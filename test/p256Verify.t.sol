// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import {Test, console, console2} from "forge-std/Test.sol";
import "forge-std/StdJson.sol";
import "FreshCryptoLib/FCL_ecdsa.sol";
import "FreshCryptoLib/FCL_ecdsa_utils.sol";
import "p256-verifier/src/P256.sol";
import "p256-verifier/src/P256Verifier.sol";

contract P256VerifyTest is Test {
    using stdJson for string;
    uint constant N = uint(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551);

    function setUp() public {
        vm.etch(P256.VERIFIER, type(P256Verifier).runtimeCode);
    }

    function test_fuzzVerifyTrue(uint pk, bytes32 digest) public {
        vm.assume(pk < N);
        vm.assume(pk > 0);
        (uint x, uint y) = FCL_ecdsa_utils.ecdsa_derivKpub(pk);
        (bytes32 r, bytes32 s) = vm.signP256(pk, digest);
        assertTrue(P256.verifySignatureAllowMalleability(digest, uint(r), uint(s), x, y));
        assertTrue(FCL_ecdsa.ecdsa_verify(digest, uint(r), uint(s), x, y));
    }

    function test_fuzzVerifyFalse(uint pk, bytes32 digest, uint r, uint s) public {
        vm.assume(pk < N);
        vm.assume(pk > 0);
        (uint x, uint y) = FCL_ecdsa_utils.ecdsa_derivKpub(pk);
        (bytes32 r_, bytes32 s_) = vm.signP256(pk, digest);
        vm.assume(uint(r_) != r);
        vm.assume(uint(s_) != s);
        assertFalse(P256.verifySignatureAllowMalleability(digest, uint(r), uint(s), x, y));
        assertFalse(FCL_ecdsa.ecdsa_verify(digest, uint(r), uint(s), x, y));
    }

    function test_fuzzVerifyFalseRandXY(uint pk, uint x, uint y, bytes32 digest, uint r, uint s) public {
        vm.assume(pk < N);
        vm.assume(pk > 0);
        (bytes32 r_, bytes32 s_) = vm.signP256(pk, digest);
        vm.assume(uint(r_) != r);
        vm.assume(uint(s_) != s);
        assertFalse(P256.verifySignatureAllowMalleability(digest, uint(r), uint(s), x, y));
        assertFalse(FCL_ecdsa.ecdsa_verify(digest, uint(r), uint(s), x, y));
    }

    struct TestVector {
        bytes Msg;
        bytes32 Qx;
        bytes32 Qy;
        bytes32 R;
        bytes32 S;
        bytes32 d;
        bytes32 k;
    }

    function test_vectors() public {
        // p256, sha-256 vectors from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures
        string memory rootPath = vm.projectRoot();
        string memory path = string.concat(rootPath, "/test/testVectors.json");
        string memory json = vm.readFile(path);
        bytes memory raw = json.parseRaw(".data");
        TestVector[] memory test = abi.decode(raw, (TestVector[]));
        for (uint i = 0; i < test.length; i++) {
            TestVector memory t = test[i];
            assertTrue(P256.verifySignatureAllowMalleability(sha256(t.Msg), uint(t.R), uint(t.S), uint(t.Qx), uint(t.Qy)));
            assertTrue(FCL_ecdsa.ecdsa_verify(sha256(t.Msg), uint(t.R), uint(t.S), uint(t.Qx), uint(t.Qy)));
        }
    }
}
