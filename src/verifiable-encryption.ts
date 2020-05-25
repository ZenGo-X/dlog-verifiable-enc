import path from 'path';
import {EncryptionResult, Helgamalsegmented, Proof, Witness} from "./common";
const bindings : any = require(path.join(__dirname, '../../../native'));

export function encrypt(encryptionKey: Buffer, secret: Buffer): EncryptionResult {
    const res = JSON.parse(bindings.ve_encrypt(encryptionKey.toString('hex'), secret.toString('hex')));
    const witness: Witness = Witness.fromPlain(res[0]);
    const ciphertexts: Helgamalsegmented = Helgamalsegmented.fromPlain(res[1]);
    return { witness, ciphertexts };
}

export function decrypt(decryptionKey: Buffer, ciphertexts: Helgamalsegmented): Buffer {
    const secretKeyHex: string = bindings.ve_decrypt(
        decryptionKey.toString('hex'),
        JSON.stringify(ciphertexts)
    );
    return Buffer.from(secretKeyHex.padStart(64, '0'), 'hex');
}

export function prove(encryptionKey: Buffer, encryptionResult: EncryptionResult): Proof {
    console.log('encryptionResult.witness =', encryptionResult.witness);
    const proof = JSON.parse(
        bindings.ve_prove(
            encryptionKey.toString('hex'),
            JSON.stringify(encryptionResult.witness),
            JSON.stringify(encryptionResult.ciphertexts))
    );
    return Proof.fromPlain(proof);
}

export function verify(proof: Proof, encryptionKey: Buffer, publicKey: Buffer, ciphertexts: Helgamalsegmented): boolean {
    return bindings.ve_verify(
        JSON.stringify(proof),
        encryptionKey.toString('hex'),
        publicKey.toString('hex'),
        JSON.stringify(ciphertexts));
}
