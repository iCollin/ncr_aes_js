var aesjs = require('aes-js');
const crypto = require('crypto');

class mc256 {
    static _mc_256 = `⅛⅜⅝⅞⅓⅔✉☂☔☄⛄☃⚐✎❣♤♧♡♢⛈ªº¬«»░▒▓∅∈≡±≥≤⌠⌡÷≈°∙√ⁿ²¡‰­·₴≠×ΦΨικλοπτυφЯабвгдежзиклмнопрстуфхцчшщъыьэюяєѕіј„…⁊←↑→↓⇄＋ƏəɛɪҮүӨөʻˌ;ĸ⁰¹³⁴⁵⁶⁷⁸⁹⁺⁻⁼⁽⁾ⁱ™⧈⚔☠ᴀʙᴄᴅᴇꜰɢʜᴊᴋʟᴍɴᴏᴘꞯʀꜱᴛᴜᴠᴡʏᴢ¢¤¥©®µ¶¼½¾·‐‚†‡•‱′″‴‵‶‷‹›※‼⁂⁉⁎⁑⁒⁗℗−∓∞☀☁☈Є☲☵☽♀♂⚥♠♣♥♦♩♪♫♬♭♮♯⚀⚁⚂⚃⚄⚅ʬ⚡⛏✔❄❌❤⭐△▷▽◁◆◇○◎☆★✘⸸▲▶▼◀●◦◘⚓ᛩᛪ☺☻`;

    static encode(a) {
        var b = '';
        for (var c of a) {
            b += this._mc_256.charAt(c);
        }
        return b;
    }

    static decode(a) {
        var b = [];
        for (var c of a) {
            b.push(this._mc_256.indexOf(c));
        }
        return b;
    }
}

const c0 = 0xe66dn;
const c1 = 0xdeecn;
const c2 = 0x0005n;
const on_16 = 0xffffn;
function gen_iv(nonce) {
    var iv = Array(16);
    const seed = BigInt('0x' + nonce.map(b => b.toString(16).padStart(2, '0')).join(''));
    var s0 = (seed & on_16) ^ c0;
    var s1 = ((seed / 0x10000n) & on_16) ^ c1;
    var s2 = ((seed / 0x100000000n) & on_16) ^ c2;
    function next() {
        let carry = 0xbn;
        let r0 = (s0 * c0) + carry;
        carry = r0 >> 16n;
        r0 &= on_16;

        let r1 = (s1 * c0 + s0 * c1) + carry;
        carry = r1 >> 16n;
        r1 &= on_16;

        let r2 = (s2 * c0 + s1 * c1 + s0 * c2) + carry;
        r2 &= on_16;
        [s0, s1, s2] = [r0, r1, r2];
        return s2 * 0x10000n + s1;
    }
    for (let i = 0; i < 16;) {
        for (let r = next(), n = Math.min(16-i, 4); n-- > 0; r >>= 8n) {
            iv[i++] = (r << 24n) >> 24n;
        }
    }
    return iv.map(b => Number(0xffn&b));
}

function encrypt(key, a, nonce=null) {
    if (!a.startsWith('#%')) { a = '#%' + a; }
    if (nonce == null) { nonce = [...crypto.randomBytes(8)]; }
    const iv = gen_iv(nonce);
    var plain_bytes = [...(new TextEncoder().encode(a))]; 
    const aes = new aesjs.ModeOfOperation.cfb(key, iv, 1);
    const encr = aes.encrypt(plain_bytes);
    for (let b of encr) { nonce.push(b) }
    return mc256.encode(nonce);
}

function decrypt(key, e) {
    if (e.length < 9) return null;
    try {
        const dec = mc256.decode(e);
        const iv = gen_iv(dec.slice(0, 8));
        const aes = new aesjs.ModeOfOperation.cfb(key, iv, 1);
        const decr = aes.decrypt(dec.slice(8));
        const plain = new TextDecoder().decode(decr)
        return plain.startsWith('#%') ? plain.substring(2) : null;
    } catch (err) {
        //console.log('error decrypting', err);
    }
    return null;
}

module.exports = {
    gen_iv,
    encrypt,
    decrypt
}

