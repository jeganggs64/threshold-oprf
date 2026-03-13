/** Stored device key entry for Apple App Attest. */
export interface DeviceKeyEntry {
  keyId: string;
  publicKey: string; // PEM-encoded EC public key
  counter: number;
  createdAt: number;
}

/** Interface for persisting Apple App Attest device keys. */
export interface DeviceKeyStore {
  saveKey(keyId: string, publicKey: string, counter: number): Promise<void>;
  getKey(keyId: string): Promise<DeviceKeyEntry | null>;
  updateCounter(keyId: string, counter: number): Promise<void>;
}
