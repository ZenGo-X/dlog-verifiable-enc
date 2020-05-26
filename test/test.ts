import {ve, gr} from '../src';
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

describe('Test gradual release', () => {

    interface Party {
        decryptionKey: Buffer,
        encryptionKey: Buffer,
        secretKey: Buffer,
        publicKey: Buffer,
    }

    let p1: Party;
    let p2: Party;

    before(() => {
        function createParty(): Party {
            const encKeyPair = ec.genKeyPair();
            const decryptionKey = encKeyPair
                .getPrivate()
                .toBuffer();
            const encryptionKey = Buffer.from(
                encKeyPair
                    .getPublic()
                    .encode('hex', false)
                    .substr(2), // (x,y)
                'hex');

            const keyPair = ec.genKeyPair();
            const secretKey = keyPair
                .getPrivate()
                .toBuffer();
            const publicKey = Buffer.from(
                keyPair
                    .getPublic()
                    .encode('hex', false)
                    .substr(2),  // (x,y)
                'hex');

            return {
                decryptionKey,
                encryptionKey,
                secretKey,
                publicKey,
            };
        }

        p1 = createParty();
        p2 = createParty();
    });

    it('creates share', () => {
        // parties exchange encryption keys, each encrypts to segments
        const [p1FirstMessage, p1Share] = gr.createShare(
            p1.secretKey,
            p2.encryptionKey
        );
        const [p2FirstMessage, p2Share] = gr.createShare(
            p2.secretKey,
            p1.encryptionKey
        );

        // p1 sends first message to p2
        assert(gr.verifyStart(p1FirstMessage, p2.encryptionKey));
        // p2 sends first message to p1
        assert(gr.verifyStart(p2FirstMessage, p1.encryptionKey));

        // prove & verify segment by segment
        const p1SegmentProofs = [];
        const p2SegmentProofs = [];
        for (let i = 0; i < p1Share.getNumberOfSegments(); i++) {
            // p1 proves
            const p1SegmentProof = p1Share.proveSegment(i);
            // p1 sends segment proof to p2, p2 verifies
            assert(gr.verifySegment(p1FirstMessage, p1SegmentProof, p2.encryptionKey));
            p1SegmentProofs.push(p1SegmentProof);

            // p2 proves
            const p2SegmentProof = p2Share.proveSegment(i);
            // p2 sends segment proof to p1, p1 verifies
            assert(gr.verifySegment(p2FirstMessage, p2SegmentProof, p1.encryptionKey));
            p2SegmentProofs.push(p2SegmentProof);
        }

        // p1 and p2 can now extract the counterparty's secret
        const p1SecretKeyCandidate = gr.extractSecret(p1FirstMessage, p1SegmentProofs, p2.decryptionKey);
        assert(p1SecretKeyCandidate.equals(p1.secretKey));

        const p2SecretKeyCandidate = gr.extractSecret(p2FirstMessage, p2SegmentProofs, p1.decryptionKey);
        assert(p2SecretKeyCandidate.equals(p2.secretKey));
    });
});