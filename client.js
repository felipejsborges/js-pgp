let localStorage = {}

function saveLocally(key, value) {
	localStorage[key] = value
}

function getFromLocal(key) {
	return localStorage[key]
}

export { saveLocally, getFromLocal }
