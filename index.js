import * as client from "./client.js"
import * as server from "./server.js"
import * as common from "./common.js"

const defaultKeys = common.generateKeyPair()
const defaultServerPublicKey = common.publicKeyToPem(defaultKeys.publicKey)
const defaultServerPrivateKey = common.privateKeyToPem(defaultKeys.privateKey)

// Inicia o fluxo de login
const loginData = { 'email': 'exemplo@email.com' }

const clientKeyPairForLogin = common.generateKeyPair()
console.log('Gerado um novo Client Key Pair para utilização na request de criação de sessão')

const createSessionPayload = { loginData, clientPublicKey: common.publicKeyToPem(clientKeyPairForLogin.publicKey) }
const encryptedLoginData = common.hybridEncrypt(createSessionPayload, common.publicKeyFromPem(defaultServerPublicKey))
console.log('Client criptografou os dados de login e sua chave pública, utilizando a Default Server Public Key')

console.log('Enviando request ao servidor...')

const decryptedLoginData = common.hybridDecrypt(encryptedLoginData, common.privateKeyFromPem(defaultServerPrivateKey))
console.log('Servidor descriptografou o payload do login utilizando o Default Server Private Key')

const serverKeyPair = common.generateKeyPair()
console.log('Servidor criou um novo Server Key Pair para a sessão que está sendo criada')

const { publicKey, privateKey, iv } = common.encryptKeyPair(serverKeyPair)
console.log('Servidor criptografou as chaves geradas')

server.createSession({ email: decryptedLoginData.loginData.email, privateKey, publicKey, iv })
console.log('Servidor salvou as chaves criptografadas no banco de dados, vinculando com o usuário')

const sessionCreationReturnPayload = { serverPublicKey: common.publicKeyToPem(serverKeyPair.publicKey), email: decryptedLoginData.loginData.email }
const encryptedSessionCreationReturnPayload = common.hybridEncrypt(sessionCreationReturnPayload, common.publicKeyFromPem(decryptedLoginData.clientPublicKey))
console.log('Servidor criptografou os dados da sessão juntamente com sua chave pública, utilizando o Client Public Key criado para realização do login')

console.log('Enviando retorno ao client...')

const decryptedReturn = common.hybridDecrypt(encryptedSessionCreationReturnPayload, clientKeyPairForLogin.privateKey)
console.log('Client descriptografou o retorno do login, utilizando Client Private Key')

client.saveLocally('SESSION_DATA', decryptedReturn) // na prática, será criptografado antes de salvar
console.log('Client armazenou os dados da sessão localmente')

// Completa o fluxo de login e criação da sessão.
// Chave pública do servidor está salva de forma segura
// Client Key Pair para login não existe mais

// Exemplo de fluxo para toda e qualquer request
const clientKeyPairForRequest = common.generateKeyPair()
console.log('Gerado um novo Client Key Pair para uma request')

const { serverPublicKey, email } = client.getFromLocal('SESSION_DATA')
const requestPayload = {
	data: { 'sample': '1' },
	clientPublicKey: common.publicKeyToPem(clientKeyPairForRequest.publicKey),
}
const encryptedRequestPayload = common.hybridEncrypt(requestPayload, common.publicKeyFromPem(serverPublicKey))
console.log('Client criptografou os dados da request e sua chave pública, utilizando o Server Public Key')

console.log('Enviando request ao servidor...')

const sessionData = server.getSessionByEmail(email)
const userPrivateKey = common.decryptKeyPair(sessionData.publicKey, sessionData.privateKey, sessionData.iv).privateKey
const decryptedRequestPayload = common.hybridDecrypt(encryptedRequestPayload, common.privateKeyFromPem(userPrivateKey))
console.log('Servidor descriptografou o payload com a Server Private Key gerado para o usuário ao criar sessão')

console.log('Servidor realizou as operações da request')

const returnPayload = { data: { 'sample': '2' } }
const encryptedReturnPayload = common.hybridEncrypt(returnPayload, common.publicKeyFromPem(decryptedRequestPayload.clientPublicKey))
console.log('Servidor criptografou o retorno utilizando a Client Public Key')

const decryptedReturnPayload = common.hybridDecrypt(encryptedReturnPayload, clientKeyPairForRequest.privateKey)
console.log('Client recebeu o retorno e descriptografou com a Client Private Key')

console.log('Fluxo finalizado!')
	// Client Key Pair não existem
	// Assim que iniciar uma nova request, um novo Client Key Pair é gerado
	// Server Key Pair é excluído sempre que o usuário faz logout
