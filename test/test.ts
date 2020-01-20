import ve from '../src';
import assert from 'assert';
import {ec as EC} from 'elliptic';
const ec = new EC('secp256k1');

describe('Test verifiable DL encryption', () => {
    let decryptionKeyHex: string;
    let encryptionKeyHex: string;
    let secretKeyHex: string;
    let publicKeyHex: string;

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
        const { ciphertexts } = ve.encrypt(encryptionKeyHex, secretKeyHex);
        const secretKeyHexNew = ve.decrypt(decryptionKeyHex, ciphertexts);
        assert(secretKeyHexNew === secretKeyHex,
            'value returned from decryption does not equal the encrypted secret');
    });

    it('prove encryption of discrete logarithm', () => {
        const encryptionResult = ve.encrypt(encryptionKeyHex, secretKeyHex);
        const proof = ve.prove(encryptionKeyHex, encryptionResult);
        const isVerified = ve.verify(proof, encryptionKeyHex, publicKeyHex, encryptionResult.ciphertexts);
        assert(isVerified, "failed proof verification");
    });
});
