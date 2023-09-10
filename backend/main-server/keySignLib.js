const crypto = require('crypto');

class KeySignLib {
    #keyString = "851cdd7f64d533691714394a65ed90199cec9351f8bff9ea78875f3fe9d8edcf";
    #ivString = "2bca39e75756cd056b244de79a565c08";
    #key = Buffer.from(this.#keyString, 'hex');
    #iv = Buffer.from(this.#ivString, 'hex');
    #algorithm = 'aes-256-cbc';
    #randomBytesNumber = 30;
    #text = "voice verified";

    generateSign() {
        // Generate random bytes for entropy
        const randomBytesBefore = crypto.randomBytes(this.#randomBytesNumber);
        const randomBytesAfter = crypto.randomBytes(this.#randomBytesNumber);
        // Combine random bytes and text
        const combinedText = Buffer.concat([randomBytesBefore, Buffer.from(this.#text), randomBytesAfter]);

        const cipher = crypto.createCipheriv(this.#algorithm, this.#key, this.#iv);
        let encrypted = cipher.update(combinedText);
        encrypted = Buffer.concat([encrypted, cipher.final()]);

        return encrypted.toString('hex');
    }

    checkSign(encryptedText) {
        const decipher = crypto.createDecipheriv(this.#algorithm, this.#key, this.#iv);
        let decrypted = decipher.update(Buffer.from(encryptedText, 'hex'));
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        // Remove random bytes (30 bytes from the beginning and 30 from the end)
        return decrypted.slice(this.#randomBytesNumber, decrypted.length - this.#randomBytesNumber).toString() === this.#text;
    }
}

const keySignLibInstance = new KeySignLib();

module.exports = keySignLibInstance;
