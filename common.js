import forge from "node-forge";
const { pki } = forge

const defaultKey = "aPdSgVkYp3s6v9y$"

function generateKeyPair() {
	return pki.rsa.generateKeyPair({ bits: 2048 });
}

function symmetricEncrypt(payload, key, iv) {
	const cipher = forge.cipher.createCipher('AES-CBC', key);
	cipher.start({ iv });
	cipher.update(forge.util.createBuffer(JSON.stringify(payload)));
	cipher.finish();
	const base64EncodedOutput = forge.util.encode64(cipher.output.getBytes())
	return base64EncodedOutput
}

function symmetricDecrypt(encryptedPayload, key, iv) {
	const base64DecodedPayload = forge.util.decode64(encryptedPayload)
	const decipher = forge.cipher.createDecipher('AES-CBC', key);
	decipher.start({ iv });
	decipher.update(forge.util.createBuffer(base64DecodedPayload));
	decipher.finish();
	return decipher.output.data
}

function encryptKeyPair(keyPair) {
	const iv = forge.random.getBytesSync(16)
	const encryptedPublicKey = symmetricEncrypt(publicKeyToPem(keyPair.publicKey), defaultKey, iv)
	const encryptedPrivateKey = symmetricEncrypt(privateKeyToPem(keyPair.privateKey), defaultKey, iv)
	return { publicKey: encryptedPublicKey, privateKey: encryptedPrivateKey, iv }
}

function decryptKeyPair(publicKey,privateKey,iv) {
	const decryptedPublicKey = symmetricDecrypt(publicKey, defaultKey,iv)
	const decryptedPrivateKey = symmetricDecrypt(privateKey, defaultKey,iv)
	return { publicKey: decryptedPublicKey, privateKey: decryptedPrivateKey }
}

function hybridEncrypt(payload, publicKey) {
	const key = forge.random.getBytesSync(16);
	const iv = forge.random.getBytesSync(16);
	const symmetricEncryptedPayload = symmetricEncrypt(payload, key, iv)
	const rsaEncryptedPayload = publicKey.encrypt(JSON.stringify({ key, iv }))
	const base64EncodedRsaEncryptedPayload = forge.util.encode64(rsaEncryptedPayload)
	return { symmetric: symmetricEncryptedPayload, asymmetric: base64EncodedRsaEncryptedPayload }
}

function hybridDecrypt(encryptedPayload, privateKey) {
	const { symmetric, asymmetric } = encryptedPayload
	const base64DecodedAsymmetric = forge.util.decode64(asymmetric)
	const rsaDecryptedPayload = privateKey.decrypt(base64DecodedAsymmetric)
	const { key, iv } = JSON.parse(rsaDecryptedPayload)
	const symmetricDecryptedPayload = symmetricDecrypt(symmetric, key, iv)
	return JSON.parse(symmetricDecryptedPayload)
}

function publicKeyToPem(publicKey) {
	return pki.publicKeyToPem(publicKey)
}

function privateKeyToPem(privateKey) {
	return pki.privateKeyToPem(privateKey)
}

function publicKeyFromPem(pemPublicKey) {
	let parsedPemPublicKey = pemPublicKey
	while (parsedPemPublicKey.includes('\\n')) {
		parsedPemPublicKey = parsedPemPublicKey.replace('\\n', '\n')
	}
	while (parsedPemPublicKey.includes('\\r')) {
		parsedPemPublicKey = parsedPemPublicKey.replace('\\r', '\r')
	}
	return pki.publicKeyFromPem(parsedPemPublicKey)
}

function privateKeyFromPem(pemPrivateKey) {
	let parsedPemPrivateKey = pemPrivateKey
	while (parsedPemPrivateKey.includes('\\n')) {
		parsedPemPrivateKey = parsedPemPrivateKey.replace('\\n', '\n')
	}
	while (parsedPemPrivateKey.includes('\\r')) {
		parsedPemPrivateKey = parsedPemPrivateKey.replace('\\r', '\r')
	}
	return pki.privateKeyFromPem(parsedPemPrivateKey)
}

export { generateKeyPair, encryptKeyPair, decryptKeyPair, hybridEncrypt, hybridDecrypt, publicKeyToPem, privateKeyToPem, publicKeyFromPem, privateKeyFromPem }
