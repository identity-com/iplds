import { CryptoDecryptKeyAgreement, CryptoKeyAgreement, ICryptoProvider } from './ICryptoProvider';
import { DecryptKeyAgreement, KeyAgreement } from './types';

export abstract class AbstractCryptoProvider<ECDHKey, CEKKey, KWKey>
  implements ICryptoProvider<ECDHKey, CEKKey, KWKey>
{
  public fromProviderSpecificKeyAgreement = async (
    specificAgreement: CryptoKeyAgreement<ECDHKey, CEKKey>,
  ): Promise<KeyAgreement> => {
    const agreement: KeyAgreement = {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      cek:
        specificAgreement.cek instanceof Uint8Array
          ? await this.fromRawCEKKey(specificAgreement.cek)
          : await this.fromCEKKey(specificAgreement.cek),

      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      encryptedKey: specificAgreement.encryptedKey,

      parameters: {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        epk: await this.fromECDHKey(specificAgreement.parameters.epk),
      },
    };
    return agreement;
  };

  public providerSpecificKeyAgreement = async (
    keyAgreement: DecryptKeyAgreement,
  ): Promise<CryptoDecryptKeyAgreement<ECDHKey>> => {
    return {
      encryptedKey: keyAgreement.encryptedKey,
      parameters: {
        epk: await this.toECDHKey(keyAgreement.parameters.epk),
      },
    };
  };

  abstract toECDHKey(jwk: JsonWebKey, usage?: KeyUsage[]): Promise<ECDHKey>;
  abstract fromECDHKey(ecdhKey: ECDHKey): Promise<JsonWebKey>;

  abstract toRawCEKKey(jwk: JsonWebKey, usage?: KeyUsage[]): Promise<Uint8Array>;
  abstract fromRawCEKKey(rawCEKKey: Uint8Array): Promise<JsonWebKey>;

  abstract toCEKKey(jwk: JsonWebKey, usage?: KeyUsage[]): Promise<CEKKey>;
  abstract fromCEKKey(cekKey: CEKKey): Promise<JsonWebKey>;

  abstract fromKWKey(kwKey: KWKey): Promise<JsonWebKey>;
}
