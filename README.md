# RClone Crypt

RClone Crypt algorithm subset implemented in TypeScript/JavaScript. 

This is basically some line-to-line translations of [`rclone/backend/crypt/cipher.go`](https://github.com/rclone/rclone/blob/master/backend/crypt/cipher.go) and [`rclone/backend/crypt/cipher_test.go`](https://github.com/rclone/rclone/blob/master/backend/crypt/cipher_test.go), with limited features.

# Why

Because I'd like to encrypt files using widely-used rclone format in TypeScript/JavaScript.

# Usage

```bash
npm install @fyears/rclone-crypt
```

```typescript

import { Cipher } from "@fyears/rclone-crypt";
import { deepStrictEqual } from "assert";

(async function(){
    const password = "custom-password";
    const salt = "custom-salt";
    const cipher = new Cipher();
    await cipher.key(password, salt);

    const fileName = "custom-dir/custom-filename";
    const encFileName = await cipher.encryptFileName(fileName);
    console.log(encFileName);
    const recoveredFileName = await cipher.decryptFileName(encFileName);
    console.log(recoveredFileName);
    deepStrictEqual(fileName, recoveredFileName);
    
    const fileContent = new Uint8Array([1,2,3,4,5]); // user provided
    const encFileContent = await cipher.encryptData(fileContent);
    console.log(encFileContent);
    const recoveredFileContent = await cipher.decryptData(encFileContent);
    console.log(recoveredFileContent);
    deepStrictEqual(fileContent, recoveredFileContent);
})();
```

# Features

* [x] file name encryption/decryption
* [x] file content encryption
* [x] many tests
* [ ] streaming encryption/decryption
* [ ] ~~file name obfuscate (not planned)~~
