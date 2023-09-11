const crypto = require('crypto');
class KeySignLib {
    // Private class variables for encryption key, initialization vector, and algorithm
    #keyString = "851cdd7f64d533691714394a65ed90199cec9351f8bff9ea78875f3fe9d8edcf";
    #ivString = "2bca39e75756cd056b244de79a565c08";
    #key = Buffer.from(this.#keyString, 'hex');
    #iv = Buffer.from(this.#ivString, 'hex');
    #algorithm = 'aes-256-cbc';
    // Number of random bytes to add before and after the text for additional entropy
    #randomBytesNumber = 30;
    // Text to be encrypted and verified
    #text = "voice verified";
    generateSign() {
        // Generate random bytes for entropy before and after the text
        // This adds an additional layer of security by making the encrypted text unique each time
        const randomBytesBefore = crypto.randomBytes(this.#randomBytesNumber);
        const randomBytesAfter = crypto.randomBytes(this.#randomBytesNumber);
        // Combine the random bytes and the text into a single buffer
        const combinedText = Buffer.concat([randomBytesBefore, Buffer.from(this.#text), randomBytesAfter]);
        // Create a cipher object using AES-256-CBC algorithm, key, and IV
        const cipher = crypto.createCipheriv(this.#algorithm, this.#key, this.#iv);
        // Encrypt the combined text
        let encrypted = cipher.update(combinedText);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        // Return the encrypted text as a hex string
        return encrypted.toString('hex');
    }

    checkSign(encryptedText) {
        // Create a decipher object using AES-256-CBC algorithm, key, and IV
        const decipher = crypto.createDecipheriv(this.#algorithm, this.#key, this.#iv);
        // Decrypt the encrypted text
        let decrypted = decipher.update(Buffer.from(encryptedText, 'hex'));
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        // Remove the random bytes added for entropy
        // This is done by slicing off 30 bytes from the beginning and 30 bytes from the end
        const originalText = decrypted.slice(this.#randomBytesNumber, decrypted.length - this.#randomBytesNumber).toString();
        // Check if the decrypted text matches the original text
        return originalText === this.#text;
    }
}

// Create an instance of the KeySignLib class
const keySignLibInstance = new KeySignLib();
// Export the instance for use in other modules
module.exports = keySignLibInstance;
