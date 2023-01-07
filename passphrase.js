const crypto = require('crypto');

if (!process.argv[2]) {
    console.log('usage: node passphrase.js <passphrase>');
    process.exit(1);
}

salt = '2d4818490b0c0a95faa5444701d99977';
crypted = crypto.pbkdf2Sync(process.argv[2], Buffer.from(salt, 'hex'), 65536, 16, 'sha1');
console.log(crypted.toString('base64'));
