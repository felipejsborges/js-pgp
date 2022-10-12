let sessions = []

function createSession(sessionData) {
	sessions.push(sessionData)
}

function getSessionByEmail(email) {
	return sessions.find(session => email === session.email)
}

export { createSession, getSessionByEmail }
