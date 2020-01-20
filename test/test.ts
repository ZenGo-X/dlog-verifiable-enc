import ve from '../src';
import assert from 'assert';
import {ec as EC} from 'elliptic';
const ec = new EC('secp256k1');

describe('Test verifiable DL encryption', () => {
    let decryptionKey: Buffer;
    let encryptionKey: Buffer;
    let secretKey: Buffer;
    let publicKey: Buffer;

    before(() => {
        const encKeyPair = ec.genKeyPair();
        decryptionKey = encKeyPair
            .getPrivate()
            .toBuffer();
        encryptionKey = Buffer.from(
            encKeyPair
                .getPublic()
                .encode('hex', false)
                .substr(2), // (x,y)
            'hex');

        const keyPair = ec.genKeyPair();
        secretKey = keyPair
            .getPrivate()
            .toBuffer();
        publicKey = Buffer.from(
            keyPair
                .getPublic()
                .encode('hex', false)
                .substr(2),  // (x,y)
            'hex');
    });

    it('decrypt encryption', () => {
        const { ciphertexts } = ve.encrypt(encryptionKey, secretKey);
        const secretKeyNew = ve.decrypt(decryptionKey, ciphertexts);
        assert(secretKeyNew.equals(secretKey),
            'value returned from decryption does not equal the encrypted secret');
    });

    it('prove encryption of discrete logarithm', () => {
        const encryptionResult = ve.encrypt(encryptionKey, secretKey);
        const proof = ve.prove(encryptionKey, encryptionResult);
        const isVerified = ve.verify(proof, encryptionKey, publicKey, encryptionResult.ciphertexts);
        assert(isVerified, "failed proof verification");
    });
});
