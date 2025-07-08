const express = require('express');
const path = require('path');
const fs = require('fs').promises;
const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');

const app = express();
const PORT = 8002;
const USERS_DB_PATH = path.join(__dirname, 'users.json');

// In a real application, you'd store user data in a database.
// For this example, we'll use a JSON file.

// WebAuthn RP ID and Origin
const rpID = 'localhost'; // Your website's domain (e.g., 'example.com')
const origin = `http://localhost:${PORT}`; // Your website's origin

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Helper functions for reading/writing users.json
async function readUsers() {
    try {
        const data = await fs.readFile(USERS_DB_PATH, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') {
            // File does not exist, return empty object
            return {};
        }
        throw error;
    }
}

async function writeUsers(users) {
    await fs.writeFile(USERS_DB_PATH, JSON.stringify(users, null, 2), 'utf8');
}

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/home', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

// User registration (username/password)
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const users = await readUsers();

    if (users[username]) {
        return res.status(400).json({ message: 'Username already exists' });
    }

    users[username] = {
        password: password, // In a real app, hash this password!
        authenticators: [], // For WebAuthn credentials
        currentChallenge: undefined, // For WebAuthn challenges
    };
    await writeUsers(users);

    res.status(201).json({ message: 'User registered successfully' });
});

// User login (username/password)
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const users = await readUsers();

    const user = users[username];

    if (!user || user.password !== password) {
        return res.status(401).json({ message: 'Invalid username or password' });
    }

    res.status(200).json({ message: 'Login successful', username: username });
});

// WebAuthn Registration
app.post('/register-passkey-challenge', async (req, res) => {
    const { username } = req.body;
    const users = await readUsers();
    const user = users[username];

    if (!user) {
        return res.status(400).json({ message: 'User not found' });
    }

    const options = await generateRegistrationOptions({
        rpName: 'Simple Passkey Auth',
        rpID,
        userID: new TextEncoder().encode(username),
        userName: username,
        attestationType: 'none',
        excludeCredentials: user.authenticators.map(authenticator => ({
            id: authenticator.credentialID,
            type: 'public-key',
        })),
        authenticatorSelection: {
            residentKey: 'required',
            userVerification: 'preferred',
        },
    });

    user.currentChallenge = options.challenge;
    await writeUsers(users);

    res.json(options);
});

app.post('/register-passkey', async (req, res) => {
    const { username, attResp } = req.body;
    const users = await readUsers();
    const user = users[username];

    if (!user) {
        return res.status(400).json({ message: 'User not found' });
    }

    let verification;
    try {
        verification = await verifyRegistrationResponse({
            response: attResp,
            expectedChallenge: user.currentChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
        });
    } catch (error) {
        console.error(error);
        return res.status(400).json({ message: error.message });
    }

    const { verified, registrationInfo } = verification;

    if (verified && registrationInfo) {
        const { credentialPublicKey, credentialID, counter } = registrationInfo;

        const newAuthenticator = {
            credentialID,
            credentialPublicKey: Buffer.from(credentialPublicKey).toString('base64'),
            counter,
            transports: attResp.response.transports,
        };
        user.authenticators.push(newAuthenticator);
        user.currentChallenge = undefined;
        await writeUsers(users);

        res.json({ verified });
    } else {
        res.status(400).json({ message: 'Registration failed' });
    }
});

// WebAuthn Authentication
app.post('/login-passkey-challenge', async (req, res) => {
    const { username } = req.body;
    const users = await readUsers();
    const user = users[username];

    if (!user) {
        return res.status(400).json({ message: 'User not found' });
    }

    if (user.authenticators.length === 0) {
        return res.status(400).json({ message: 'No passkeys registered for this user' });
    }

    const options = await generateAuthenticationOptions({
        rpID,
        allowCredentials: user.authenticators.map(authenticator => ({
            id: authenticator.credentialID,
            type: 'public-key',
            transports: authenticator.transports,
        })),
        userVerification: 'preferred',
    });

    user.currentChallenge = options.challenge;
    await writeUsers(users);

    res.json(options);
});

app.post('/login-passkey', async (req, res) => {
    const { username, authResp } = req.body;
    const users = await readUsers();
    const user = users[username];

    if (!user) {
        return res.status(400).json({ message: 'User not found' });
    }

    const authenticator = user.authenticators.find(auth => auth.credentialID === authResp.id);

    if (!authenticator) {
        return res.status(400).json({ message: 'Authenticator not found' });
    }

    let verification;
    try {
        verification = await verifyAuthenticationResponse({
            response: authResp,
            expectedChallenge: user.currentChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            authenticator: {
                credentialID: authenticator.credentialID,
                credentialPublicKey: Buffer.from(authenticator.credentialPublicKey, 'base64'),
                counter: authenticator.counter,
            },
        });
    } catch (error) {
        console.error(error);
        return res.status(400).json({ message: error.message });
    }

    const { verified, authenticationInfo } = verification;

    if (verified) {
        authenticator.counter = authenticationInfo.newCounter;
        user.currentChallenge = undefined;
        await writeUsers(users);

        res.json({ verified });
    } else {
        res.status(400).json({ message: 'Authentication failed' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
