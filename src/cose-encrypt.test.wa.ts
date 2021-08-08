import * as coseEncrypt from './joseEncrypt'
import { encode as cborEncode} from 'cborg'

async function main() {
    
    const privateKey = await crypto.subtle.importKey(
        "jwk", 
        {
            "kty":"EC",
            // "kid":"meriadoc.brandybuck@buckland.example",
            "crv":"P-256",
            "x":"Ze2loSV3wrroKUN_4zhwGhCqo3Xhu1td4QjeQ5wIVR0",
            "y":"HlLtdXARY_f55A3fnzQbPcm6hgr34Mp8p-nuzQCE0Zw",
            "d":"r_kHyZ-a06rmxM3yESK84r1otSg-aQcVStkRhA-iCM8"
        },
        {
            name: "ECDH",
            namedCurve: "P-256",
        },
        false,
        []
    );


    const publicKey = await crypto.subtle.importKey(
        "jwk", 
        {
            "kty":"EC",
            "crv":"P-256",
            "x":"mPUKT_bAWGHIhg0TpjjqVsP1rXWQu_vwVOHHtNkdYoA",
            "y":"8BQAsImGeAS46fyWw5MhYfGTT0IjBpFw2SS34Dv4Irs"
        },
        {
            name: "ECDH",
            namedCurve: "P-256",
        },
        false,
        []
    );

    const encryptedCose = await coseEncrypt.encrypt(
        coseEncrypt.initCose(publicKey, 'This is the content.'),
        privateKey
    );

    const cbor = encryptedCose.translateToCBOR();
    expect(Buffer.from(cborEncode(cbor)))
        .toEqual(
            Buffer.from('D8608443A10103A1054C02D1F7E6F26C43D4868D87CE5824256B748DEB647131C12A10AC261DA0628E420492A36F3DED8642B4B6FA1EB15DCEC80A0F818344A101381EA220A401022001215820687312AA4E2112CB2A06721F984788D3D1E235F64F48CEBBC81CB19E11D3F8E1225820C31C514CCB8AF91800DD519ADA41CF6B03ECDFB212FDB34D371D536C7419ACC40458246D65726961646F632E6272616E64796275636B406275636B6C616E642E6578616D706C6558289F7FF60D7189124425A470E48FF66A00B6E3D013B07C2428F2C29ECB6E605DBBADC3EA91AB671E59', 'hex'))
}


main().then(() => {console.log("done")}, console.error);