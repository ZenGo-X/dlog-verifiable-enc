export type BigInt = string;
export type FE = BigInt;

export interface GE {
    x: BigInt,
    y: BigInt
}

export class Witness {
    constructor(
        private x_vec: string[],
        private r_vec: string[]
    ) {}

    public static fromPlain(plain: any) {
        return new Witness(
            plain.x_vec,
            plain.r_vec);
    }
}

interface Helgamal {
    D: GE,
    E: GE
}

export class Helgamalsegmented {
    constructor(
        private DE: Helgamal[]
    ) {}

    public static fromPlain(plain: any): Helgamalsegmented {
        return new Helgamalsegmented(plain.DE);
    }
}

export interface HomoELGamalProof {
    T: GE,
    A3: GE,
    z1: FE,
    z2: FE,
}

export interface HomoELGamalDlogProof {
    A1: GE,
    A2: GE,
    A3: GE,
    z1: FE,
    z2: FE
}

interface InnerProductArg {
    L: GE[],
    R: GE[],
    a_tag: BigInt,
    b_tag: BigInt
}

export interface RangeProof {
    A: GE,
    S: GE,
    T1: GE,
    T2: GE,
    tau_x: FE,
    miu: FE,
    tx: FE,
    inner_product_proof: InnerProductArg
}

export class Proof {
    constructor(
        private bulletproof: RangeProof,
        private elgamal_enc: HomoELGamalProof[],
        private elgamal_enc_dlog: HomoELGamalDlogProof) {

    }

    public static fromPlain(plain: any): Proof {
        return new Proof(
            plain.bulletproof,
            plain.elgamal_enc,
            plain.elgamal_enc_dlog
        );
    }
}

export interface EncryptionResult {
    witness: Witness,
    ciphertexts: Helgamalsegmented
}