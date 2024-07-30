import fs from 'fs';
import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync, generateMnemonic as bip39GenerateMnemonic } from '@scure/bip39';
import * as english from '@scure/bip39/wordlists/english';
import { secp256k1 } from '@noble/curves/secp256k1';
import * as ccc from '@ckb-ccc/core';
import CryptoJS from 'crypto-js';
import { pbkdf2Sync } from 'crypto';

export const generateMnemonic = (strength = 128) => {
  return bip39GenerateMnemonic(english.wordlist, strength);
};

export const derivePrivateKey = (mnemonic, hdPath) => {
  const seed = mnemonicToSeedSync(mnemonic);
  const hdKey = HDKey.fromMasterSeed(seed);
  const derivedKey = hdKey.derive(hdPath);

  if (!derivedKey.privateKey) {
    throw new Error('Failed to derive private key from mnemonic');
  }

  return ccc.hexFrom(derivedKey.privateKey);
};

export const getSeed = (mnemonic) => {
  return mnemonicToSeedSync(mnemonic);
};

export const getSeedHex = (mnemonic) => {
  const seed = getSeed(mnemonic);
  return ccc.hexFrom(seed);
};

export const generatePublicKey = (privateKey) => {
  const privateKeyBytes = ccc.hexFrom(privateKey);
  const publicKey = secp256k1.getPublicKey(ccc.bytesFrom(privateKeyBytes), true);
  return ccc.hexFrom(publicKey);
};

export const expendPrivateKey = (count, startIndex = 0, seed, mnemonic, hdPath) => {
  let hdKey;

  if (seed) {
    hdKey = HDKey.fromMasterSeed(seed);
  } else if (mnemonic) {
    hdKey = HDKey.fromMasterSeed(getSeed(mnemonic));
  } else {
    throw new Error('Either seed or mnemonic must be provided');
  }

  return Array.from({ length: count }, (_, i) => {
    const index = startIndex + i;
    const path = hdPath ? `${hdPath.slice(0, -1)}${index}` : `m/44'/0'/0'/0/${index}`;
    const expendedPrivatekey = hdKey.derive(path);

    if (!expendedPrivatekey.privateKey) {
      throw new Error(`Failed to derive private key for path: ${path}`);
    }

    const privateKey = ccc.hexFrom(expendedPrivatekey.privateKey);
    const publicKey = generatePublicKey(privateKey);

    return { publicKey, privateKey, path };
  });
};

export const generateMoreAccounts = (countStr, accounts, mnemonic, hdPath) => {
  const count = parseInt(countStr, 10);
  if (isNaN(count)) return [];

  const newAccounts = expendPrivateKey(count, accounts.length, undefined, mnemonic, hdPath);
  return [
    ...accounts,
    ...newAccounts.map((account) => ({
      ...account,
      address: '',
    })),
  ];
};

const encryptMnemonic = (mnemonic, password) => {
  const salt = CryptoJS.lib.WordArray.random(16);
  const iv = CryptoJS.lib.WordArray.random(16);
  const key = CryptoJS.PBKDF2(password, salt, {
    keySize: 256 / 32,
    iterations: 10000,
  });
  const encrypted = CryptoJS.AES.encrypt(mnemonic, key, { iv: iv });
  return {
    ciphertext: encrypted.ciphertext.toString(CryptoJS.enc.Hex),
    salt: salt.toString(CryptoJS.enc.Hex),
    iv: iv.toString(CryptoJS.enc.Hex),
  };
};

const decryptMnemonic = (encryptedMnemonic, password) => {
  const salt = CryptoJS.enc.Hex.parse(encryptedMnemonic.salt);
  const iv = CryptoJS.enc.Hex.parse(encryptedMnemonic.iv);
  const key = CryptoJS.PBKDF2(password, salt, {
    keySize: 256 / 32,
    iterations: 10000,
  });
  const decrypted = CryptoJS.AES.decrypt({
    ciphertext: CryptoJS.enc.Hex.parse(encryptedMnemonic.ciphertext),
  }, key, { iv: iv });
  return decrypted.toString(CryptoJS.enc.Utf8);
};

export const exportKeystore = (mnemonic, publicKey, password, filepath) => {
  const encryptedMnemonic = encryptMnemonic(mnemonic, password);
  const keystore = {
    version: 1,
    id: CryptoJS.lib.WordArray.random(16).toString(CryptoJS.enc.Hex),
    address: publicKey,
    crypto: {
      ciphertext: encryptedMnemonic.ciphertext,
      cipherparams: {
        iv: encryptedMnemonic.iv,
      },
      cipher: 'aes-128-ctr',
      kdf: 'pbkdf2',
      kdfparams: {
        dklen: 32,
        salt: encryptedMnemonic.salt,
        c: 10000,
        prf: 'hmac-sha256',
      },
      mac: CryptoJS.HmacSHA256(encryptedMnemonic.ciphertext, publicKey).toString(CryptoJS.enc.Hex),
    },
  };
  fs.writeFileSync(filepath, JSON.stringify(keystore, null, 2));
};

export const importKeystore = (filepath, password) => {
  const keystore = JSON.parse(fs.readFileSync(filepath, 'utf8'));
  const encryptedMnemonic = {
    ciphertext: keystore.crypto.ciphertext,
    iv: keystore.crypto.cipherparams.iv,
    salt: keystore.crypto.kdfparams.salt,
  };
  const mnemonic = decryptMnemonic(encryptedMnemonic, password);
  return {
    mnemonic,
    publicKey: keystore.address,
  };
};

// 示例使用
const mnemonic = generateMnemonic();
console.log('mnemonic:', mnemonic);
const hdPath = "m/44'/0'/0'/0/0";
const privateKey = derivePrivateKey(mnemonic, hdPath);
console.log('privateKey:', privateKey);
const publicKey = generatePublicKey(privateKey);
console.log('publicKey:', publicKey);

const password = 'strongpassword';
const filepath = './keystore.keystore';  // 使用 .keystore 文件扩展名

exportKeystore(mnemonic, publicKey, password, filepath);
const { mnemonic: importedMnemonic, publicKey: importedPublicKey } = importKeystore(filepath, password);

console.log(`Imported mnemonic: ${importedMnemonic}`);
console.log(`Imported publicKey: ${importedPublicKey}`);