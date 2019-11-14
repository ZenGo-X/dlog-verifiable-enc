const {encrypt, decrypt, prove, verify} = require('../dist/src');
const assert = require('assert');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');

describe('Test verifiable DL encryption', () => {
    let decryptionKeyHex;
    let encryptionKeyHex;
    let secretKeyHex;
    let publicKeyHex;

    before(() => {
        const encKeyPair = ec.genKeyPair();
        decryptionKeyHex = encKeyPair
            .getPrivate()
            .toBuffer()
            .toString('hex');
        encryptionKeyHex = encKeyPair
            .getPublic()
            .encode('hex', false)
            .substr(2);  // (x,y)

        const keyPair = ec.genKeyPair();
        secretKeyHex = keyPair
            .getPrivate()
            .toBuffer()
            .toString('hex');
        publicKeyHex = keyPair
            .getPublic()
            .encode('hex', false)
            .substr(2);  // (x,y)
    });

    it('decrypt encryption', () => {
        const { ciphertexts } = encrypt(encryptionKeyHex, secretKeyHex);
        const secretKeyHexNew = decrypt(decryptionKeyHex, ciphertexts);
        assert(typeof secretKeyHexNew === 'string');
        assert(secretKeyHexNew === secretKeyHex,
            'value returned from decryption does not equal the encrypted secret');
    });

    it('prove encryption of discrete logarithm', () => {
        const { witness, ciphertexts } = encrypt(encryptionKeyHex, secretKeyHex);
        const proof = prove(encryptionKeyHex, witness, ciphertexts);
        const isVerified = verify(proof, encryptionKeyHex, publicKeyHex, ciphertexts);
        assert(isVerified, "failed proof verification");
    });
});
