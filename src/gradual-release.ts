import path from 'path';
import {FE, GE, Helgamalsegmented, HomoELGamalDlogProof, HomoELGamalProof, Proof, RangeProof, Witness} from "./common";
const bindings : any = require(path.join(__dirname, '../../../native'));

export class Share {
    constructor(
        private secret: FE,
        private segments: Witness,
        private encryptions: Helgamalsegmented,
        private proof: Proof,
    ) {}

    public getNumberOfSegments() {
        return (this.segments as any).x_vec.length;
    }

    public proveSegment(index: number): SegmentProof {
        return JSON.parse(
          bindings.gr_segment_k_proof(
              JSON.stringify(this),
              index
          )
        );
    }

    public static fromPlain(plain: any): Share {
        return new Share(
            plain.secret,
            plain.segments,
            plain.encryptions,
            plain.proof
        );
    }
}

interface FirstMessage {
    segment_size: number,
    D_vec: GE[],
    range_proof: RangeProof,
    Q: GE,
    E: GE,
    dlog_proof: HomoELGamalDlogProof,
}

interface SegmentProof {
    k: number,
    E_k: GE,
    correct_enc_proof: HomoELGamalProof,
}

export function createShare(secret: Buffer, encryptionKey: Buffer): [FirstMessage, Share] {
    const raw: any[] = JSON.parse(
      bindings.gr_create_share(secret.toString('hex'), encryptionKey.toString('hex'))
    );
    return [raw[0], Share.fromPlain(raw[1])];
}

export function verifyStart(firstMessage: FirstMessage, encryptionKey: Buffer): boolean {
    return bindings.gr_verify_start(JSON.stringify(firstMessage), encryptionKey.toString('hex'));
}

export function verifySegment(firstMessage: FirstMessage, segmentProof: SegmentProof, encryptionKey: Buffer): boolean {
    return bindings.gr_verify_segment(
        JSON.stringify(firstMessage),
        JSON.stringify(segmentProof),
        encryptionKey.toString('hex')
    );
}

export function extractSecret(firstMessage: FirstMessage, segmentProofs: SegmentProof[], decryptionKey: Buffer): Buffer {
    const raw: string = bindings.gr_extract_secret(
        JSON.stringify(firstMessage),
        segmentProofs.map(sp => JSON.stringify(sp)),
        decryptionKey.toString('hex')
    );
    return Buffer.from(raw.padStart(64, '0'), 'hex');
}