# ncr-aes-js

NCR AES crypto JS implementation

### Dependencies

```
npm i aes-js
```

### Notes

- Only MC256 encoding is supported.
- Decoding is O(N) and could use a map...
- `passphrase.js` implements NCR key generation from passphrase

### Example Usage

```
const ncr = require('./ncr');

const key = new Buffer('7cxvMh/c/F7JU97QFRv8FA==', 'base64')

const plain = 'hello world encrypted';
console.log('plain:', plain);

const encrypted = ncr.encrypt(key, plain);
console.log('encrypted:', encrypted);

const decrypted = ncr.decrypt(key, encrypted);
console.log('decrypted:', decrypted);
```
