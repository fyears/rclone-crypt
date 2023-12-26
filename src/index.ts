import { scrypt } from "scrypt-js";
import { secretbox, randomBytes } from "tweetnacl";
import { pad, unpad } from "pkcs7-padding";

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
export const msgErrorNotAMultipleOfBlocksize = "not a multiple of blocksize";
export const msgErrorTooShortAfterDecode = "too short after base32 decode";
export const msgErrorTooLongAfterDecode = "too long after base32 decode";
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

// Cipher defines an encoding and decoding cipher for the crypt backend
export class Cipher {
  dataKey: Uint8Array; //  [32]byte                  // Key for secretbox
  nameKey: Uint8Array; //  [32]byte                  // 16,24 or 32 bytes
  nameTweak: Uint8Array; //  [nameCipherBlockSize]byte // used to tweak the name crypto
  // const block           gocipher.Block
  // const mode            NameEncryptionMode
  // const fileNameEnc     fileNameEncoding
  // const buffers         sync.Pool // encrypt/decrypt buffers
  // const cryptoRand      io.Reader // read crypto random numbers from here
  dirNameEncrypt: boolean;
  passBadBlocks: boolean; // if set passed bad blocks as zeroed blocks
  encryptedSuffix: string;

  constructor() {
    this.dataKey = new Uint8Array(32);
    this.nameKey = new Uint8Array(32);
    this.nameTweak = new Uint8Array(nameCipherBlockSize);
    this.dirNameEncrypt = true;
    this.passBadBlocks = false;
    this.encryptedSuffix = "";
  }
}

/*
 * func (c *Cipher) Key(password, salt string) (err error)
 */
export async function key(password: string, salt: string, c: Cipher) {
  const keySize = c.dataKey.length + c.nameKey.length + c.nameTweak.length;
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
  c.dataKey.set(key.slice(0, c.dataKey.length));
  c.nameKey.set(
    key.slice(c.dataKey.length, c.dataKey.length + c.nameKey.length)
  );
  c.nameTweak.set(key.slice(c.dataKey.length + c.nameKey.length));
  return c;
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

function encryptData(
  input: Uint8Array,
  nonceInput: Uint8Array | undefined,
  c: Cipher
) {
  let nonce: Uint8Array;
  if (nonceInput !== undefined) {
    nonce = nonceInput;
  } else {
    nonce = newNonce();
  }

  const res = new Uint8Array(input.byteLength);
  res.set(fileMagicBytes, 0);
  res.set(nonce, secretbox.nonceLength);

  for (
    let offset = 0, i = 0;
    offset < input.byteLength;
    offset += blockDataSize, i += 1
  ) {
    const readBuf = input.slice(offset, offset + blockDataSize);
    const buf = secretbox(readBuf, nonce, c.dataKey);
    increment(nonce);
    res.set(buf, offset + i * blockHeaderSize);
  }

  return res;
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
