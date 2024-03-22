import { scrypt } from "scrypt-js";
import { secretbox, randomBytes } from "tweetnacl";
import { pad, unpad } from "pkcs7-padding";
import { EMECipher, AESCipherBlock } from "@fyears/eme";
import { base32hex, base64url } from "rfc4648";
import * as base32768 from "base32768";

const newNonce = () => randomBytes(secretbox.nonceLength);

const nameCipherBlockSize = 16; // aes block size
const fileMagic = "RCLONE\x00\x00";
const fileMagicBytes = new TextEncoder().encode(fileMagic);
const fileMagicSize = fileMagic.length;
const fileNonceSize = 24;
const fileHeaderSize = fileMagicSize + fileNonceSize;
const blockHeaderSize = secretbox.overheadLength;
const blockDataSize = 64 * 1024;
const blockSize = blockHeaderSize + blockDataSize;
const defaultSalt = new Uint8Array([
  0xa8, 0x0d, 0xf4, 0x3a, 0x8f, 0xbd, 0x03, 0x08, 0xa7, 0xca, 0xb8, 0x3e, 0x58,
  0x1f, 0x86, 0xb1,
]);

export const msgErrorBadDecryptUTF8 = "bad decryption - utf-8 invalid";
export const msgErrorBadDecryptControlChar =
  "bad decryption - contains control chars";
export const msgErrorEncryptedFileTooShort =
  "file is too short to be encrypted";
export const msgErrorEncryptedFileBadHeader = "file has truncated block header";
export const msgErrorEncryptedBadMagic =
  "not an encrypted file - bad magic string";
export const msgErrorEncryptedBadBlock =
  "failed to authenticate decrypted block - bad password?";
export const msgErrorBadBase32Encoding = "bad base32 filename encoding";
export const msgErrorFileClosed = "file already closed";
export const msgErrorNotAnEncryptedFile =
  "not an encrypted file - does not match suffix";
export const msgErrorBadSeek = "Seek beyond end of file";
export const msgErrorSuffixMissingDot =
  "suffix config setting should include a '.'";

type FileNameEncodingType = "base32" | "base64" | "base32768";

// Cipher defines an encoding and decoding cipher for the crypt backend
export class Cipher {
  dataKey: Uint8Array; //  [32]byte                  // Key for secretbox
  nameKey: Uint8Array; //  [32]byte                  // 16,24 or 32 bytes
  nameTweak: Uint8Array;
  fileNameEnc: FileNameEncodingType;
  dirNameEncrypt: boolean;

  constructor(fileNameEnc: FileNameEncodingType = "base32") {
    this.dataKey = new Uint8Array(32);
    this.nameKey = new Uint8Array(32);
    this.nameTweak = new Uint8Array(nameCipherBlockSize);
    this.dirNameEncrypt = true;
    this.fileNameEnc = fileNameEnc;
  }

  toString() {
    return `
dataKey=${this.dataKey} 
nameKey=${this.nameKey}
nameTweak=${this.nameTweak}
dirNameEncrypt=${this.dirNameEncrypt}
fileNameEnc=${this.fileNameEnc}
`;
  }

  encodeToString(ciphertext: Uint8Array) {
    if (this.fileNameEnc === "base32") {
      return base32hex.stringify(ciphertext, { pad: false }).toLowerCase();
    } else if (this.fileNameEnc === "base64") {
      return base64url.stringify(ciphertext, { pad: false });
    } else if (this.fileNameEnc === "base32768") {
      return base32768.encode(ciphertext);
    } else {
      throw Error(`unknown fileNameEnc=${this.fileNameEnc}`);
    }
  }

  decodeString(ciphertext: string) {
    if (this.fileNameEnc === "base32") {
      if (ciphertext.endsWith("=")) {
        // should not have ending = in our seting
        throw new Error(msgErrorBadBase32Encoding);
      }
      return base32hex.parse(ciphertext.toUpperCase(), {
        loose: true,
      });
    } else if (this.fileNameEnc === "base64") {
      return base64url.parse(ciphertext, {
        loose: true,
      });
    } else if (this.fileNameEnc === "base32768") {
      return base32768.decode(ciphertext);
    } else {
      throw Error(`unknown fileNameEnc=${this.fileNameEnc}`);
    }
  }

  async key(password: string, salt: string) {
    const keySize =
      this.dataKey.length + this.nameKey.length + this.nameTweak.length;
    // console.log(`keySize=${keySize}`)
    let saltBytes = defaultSalt;
    if (salt !== "") {
      saltBytes = new TextEncoder().encode(salt);
    }
    let key: Uint8Array;
    if (password === "") {
      key = new Uint8Array(keySize);
    } else {
      key = await scrypt(
        new TextEncoder().encode(password),
        saltBytes,
        16384,
        8,
        1,
        keySize
      );
    }
    // console.log(`key=${key}`)
    this.dataKey.set(key.slice(0, this.dataKey.length));
    this.nameKey.set(
      key.slice(this.dataKey.length, this.dataKey.length + this.nameKey.length)
    );
    this.nameTweak.set(key.slice(this.dataKey.length + this.nameKey.length));
    return this;
  }

  // encryptSegment encrypts a path segment
  //
  // This uses EME with AES.
  //
  // EME (ECB-Mix-ECB) is a wide-block encryption mode presented in the
  // 2003 paper "A Parallelizable Enciphering Mode" by Halevi and
  // Rogaway.
  //
  // This makes for deterministic encryption which is what we want - the
  // same filename must encrypt to the same thing.
  //
  // This means that
  //   - filenames with the same name will encrypt the same
  //   - filenames which start the same won't have a common prefix
  async encryptSegment(plaintext: string) {
    if (plaintext === "") {
      return "";
    }
    const paddedPlaintext = pad(
      new TextEncoder().encode(plaintext) as any,
      nameCipherBlockSize
    );
    // console.log(`paddedPlaintext=${paddedPlaintext}`)
    const bc = new AESCipherBlock(this.nameKey);
    const eme = new EMECipher(bc);
    const ciphertext = await eme.encrypt(this.nameTweak, paddedPlaintext);
    // console.log(`ciphertext=${ciphertext}`)
    return this.encodeToString(ciphertext);
  }

  async encryptFileName(input: string) {
    const segments = input.split("/");
    for (let i = 0; i < segments.length; ++i) {
      // Skip directory name encryption if the user chose to
      // leave them intact
      if (!this.dirNameEncrypt && i !== segments.length - 1) {
        continue;
      }

      segments[i] = await this.encryptSegment(segments[i]);
    }
    return segments.join("/");
  }

  async decryptSegment(ciphertext: string) {
    if (ciphertext === "") {
      return "";
    }
    const rawCiphertext = this.decodeString(ciphertext);

    const bc = new AESCipherBlock(this.nameKey);
    const eme = new EMECipher(bc);
    const paddedPlaintext = await eme.decrypt(this.nameTweak, rawCiphertext);
    const plaintext = unpad(paddedPlaintext as any);
    return new TextDecoder().decode(plaintext);
  }

  async decryptFileName(input: string) {
    const segments = input.split("/");
    for (let i = 0; i < segments.length; ++i) {
      // Skip directory name encryption if the user chose to
      // leave them intact
      if (!this.dirNameEncrypt && i !== segments.length - 1) {
        continue;
      }

      segments[i] = await this.decryptSegment(segments[i]);
    }

    return segments.join("/");
  }

  async encryptData(input: Uint8Array, nonceInput: Uint8Array | undefined) {
    let nonce: Uint8Array;
    if (nonceInput !== undefined) {
      nonce = nonceInput;
    } else {
      nonce = newNonce();
    }

    const res = new Uint8Array(encryptedSize(input.byteLength));
    // console.log(`size=${encryptedSize(input.byteLength)}`)
    res.set(fileMagicBytes);
    res.set(nonce, fileMagicSize);
    // console.log(`res=${res}`)

    for (
      let offset = 0, i = 0;
      offset < input.byteLength;
      offset += blockDataSize, i += 1
    ) {
      // console.log(`i=${i}`)
      const readBuf = input.slice(offset, offset + blockDataSize);
      // console.log(`readBuf=${readBuf}`)

      const buf = secretbox(readBuf, nonce, this.dataKey);
      // console.log(`buf=${buf}`)

      increment(nonce);

      res.set(
        buf,
        fileMagicSize + fileNonceSize + offset + i * blockHeaderSize
      );
      // console.log(`res=${res}`)
    }

    // console.log(`final res=${res}`)
    return res;
  }

  async decryptData(input: Uint8Array) {
    // console.log(`input=${input}`)
    if (input.byteLength < fileHeaderSize) {
      throw Error(msgErrorEncryptedFileTooShort);
    }
    if (!compArr(input.slice(0, fileMagicSize), fileMagicBytes)) {
      throw Error(msgErrorEncryptedBadMagic);
    }
    const nonce = input.slice(fileMagicSize, fileHeaderSize);
    // console.log(`nonce=${nonce}`)

    // console.log(`dec size=${decryptedSize(input.byteLength)}`);
    const res = new Uint8Array(decryptedSize(input.byteLength));
    for (
      let offsetInput = fileHeaderSize, offsetOutput = 0, i = 0;
      offsetInput < input.byteLength;
      offsetInput += blockSize, offsetOutput += blockDataSize, i += 1
    ) {
      // console.log(`i=${i}`);
      // console.log(`offsetInput = ${offsetInput}`);
      const readBuf = input.slice(offsetInput, offsetInput + blockSize);
      // console.log(`readBuf length = ${readBuf.length}`);
      // console.log(`readBuf=${readBuf}`)

      const buf = secretbox.open(readBuf, nonce, this.dataKey);
      if (buf === null) {
        throw Error(msgErrorEncryptedBadBlock);
      }
      // console.log(`buf length = ${buf.length}`);
      // console.log(`buf=${buf}`)

      increment(nonce);

      // console.log(`offsetOutput = ${offsetOutput}`);
      res.set(buf, offsetOutput);
      // console.log(`res=${res}`)
    }

    return res;
  }
}

// func (n *nonce) carry(i int)
export function carry(i: number, n: Uint8Array) {
  for (; i < n.length; i++) {
    const digit = n[i];
    const newDigit = (digit + 1) & 0xff; // mask a bit
    n[i] = newDigit;
    if (newDigit >= digit) {
      // exit if no carry
      break;
    }
  }
}

// increment to add 1 to the nonce
// func (n *nonce) increment()
export function increment(n: Uint8Array) {
  return carry(0, n);
}

// add a uint64 to the nonce
// func (n *nonce) add(x uint64)
export function add(x: number | bigint, n: Uint8Array) {
  let y = BigInt(0);
  if (typeof x === "bigint") {
    y = BigInt.asUintN(64, x);
  } else if (typeof x === "number") {
    y = BigInt.asUintN(64, BigInt(x));
  }
  let carryNum = BigInt.asUintN(16, BigInt(0));

  for (let i = 0; i < 8; i++) {
    const digit = n[i];
    const xDigit = y & BigInt(0xff);
    y >>= BigInt(8);
    carryNum = carryNum + BigInt(digit) + BigInt(xDigit);
    n[i] = Number(carryNum);
    carryNum >>= BigInt(8);
  }
  if (carryNum !== BigInt(0)) {
    carry(8, n);
  }
}

function compArr(x: Uint8Array, y: Uint8Array) {
  if (x.length !== y.length) {
    return false;
  }
  for (let i = 0; i < x.length; ++i) {
    if (x[i] !== y[i]) {
      return false;
    }
  }
  return true;
}

export function encryptedSize(size: number) {
  const blocks = Math.floor(size / blockDataSize);
  const residue = size % blockDataSize;
  let encryptedSize =
    fileHeaderSize + blocks * (blockHeaderSize + blockDataSize);
  if (residue !== 0) {
    encryptedSize += blockHeaderSize + residue;
  }
  return encryptedSize;
}

export function decryptedSize(size: number) {
  let size2 = size;
  size2 -= fileHeaderSize;
  if (size2 < 0) {
    throw new Error(msgErrorEncryptedFileTooShort);
  }
  const blocks = Math.floor(size2 / blockSize);
  let residue = size2 % blockSize;
  let decryptedSize = blocks * blockDataSize;
  if (residue !== 0) {
    residue -= blockHeaderSize;
    if (residue <= 0) {
      throw new Error(msgErrorEncryptedFileBadHeader);
    }
  }
  decryptedSize += residue;
  return decryptedSize;
}
