const SimpleWebAuthnBrowser = window.SimpleWebAuthnBrowser;

document.addEventListener('DOMContentLoaded', () => {
    const currentPath = window.location.pathname;

    if (currentPath === '/' || currentPath === '/index.html') {
        // Logic for index.html (Login/Signup Page)
        const signupForm = document.getElementById('signupForm');
        const loginForm = document.getElementById('loginForm');
        const loginPasskeyButton = document.getElementById('loginPasskeyButton');

        const signupMessage = document.getElementById('signupMessage');
        const loginMessage = document.getElementById('loginMessage');
        const loginPasskeyMessage = document.getElementById('loginPasskeyMessage');

        if (signupForm) {
            signupForm.addEventListener('submit', async (event) => {
                event.preventDefault();
                const username = document.getElementById('signupUsername').value;
                const password = document.getElementById('signupPassword').value;

                try {
                    const response = await fetch('/register', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ username, password }),
                    });
                    const data = await response.json();
                    if (response.ok) {
                        signupMessage.textContent = data.message;
                        signupMessage.className = 'message success';
                        signupForm.reset();
                    } else {
                        signupMessage.textContent = data.message;
                        signupMessage.className = 'message error';
                    }
                } catch (error) {
                    console.error('Error during signup:', error);
                    signupMessage.textContent = 'An error occurred. Please try again.';
                    signupMessage.className = 'message error';
                }
            });
        }

        if (loginForm) {
            loginForm.addEventListener('submit', async (event) => {
                event.preventDefault();
                const username = document.getElementById('loginUsername').value;
                const password = document.getElementById('loginPassword').value;

                try {
                    const response = await fetch('/login', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ username, password }),
                    });
                    const data = await response.json();
                    if (response.ok) {
                        localStorage.setItem('loggedInUsername', data.username);
                        window.location.href = '/home';
                    } else {
                        loginMessage.textContent = data.message;
                        loginMessage.className = 'message error';
                    }
                } catch (error) {
                    console.error('Error during login:', error);
                    loginMessage.textContent = 'An error occurred. Please try again.';
                    loginMessage.className = 'message error';
                }
            });
        }

        if (loginPasskeyButton) {
            loginPasskeyButton.addEventListener('click', async () => {
                const username = prompt('Enter your username for passkey login:');
                if (!username) {
                    loginPasskeyMessage.textContent = 'Username is required for passkey login.';
                    loginPasskeyMessage.className = 'message error';
                    return;
                }

                try {
                    // 1. Request challenge from server
                    const resp = await fetch('/login-passkey-challenge', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username }),
                    });
                    const challengeOptions = await resp.json();

                    if (!resp.ok) {
                        loginPasskeyMessage.textContent = challengeOptions.message || 'Failed to get passkey login challenge.';
                        loginPasskeyMessage.className = 'message error';
                        return;
                    }

                    // 2. Pass challenge to WebAuthn API
                    const authResp = await SimpleWebAuthnBrowser.startAuthentication(challengeOptions);

                    // 3. Send response to server for verification
                    const verificationResp = await fetch('/login-passkey', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, authResp }),
                    });
                    const verificationData = await verificationResp.json();

                    if (verificationResp.ok && verificationData.verified) {
                        localStorage.setItem('loggedInUsername', username);
                        window.location.href = '/home';
                    } else {
                        loginPasskeyMessage.textContent = verificationData.message || 'Passkey login failed.';
                        loginPasskeyMessage.className = 'message error';
                    }
                } catch (error) {
                    console.error('Error during passkey login:', error);
                    loginPasskeyMessage.textContent = 'An error occurred during passkey login. Please try again.';
                    loginPasskeyMessage.className = 'message error';
                }
            });
        }

    } else if (currentPath === '/home' || currentPath === '/home.html') {
        // Logic for home.html (Homepage)
        const loggedInUsernameSpan = document.getElementById('loggedInUsername');
        const addPasskeyButton = document.getElementById('addPasskeyButton');
        const logoutButton = document.getElementById('logoutButton');
        const passkeyMessage = document.getElementById('passkeyMessage');

        const username = localStorage.getItem('loggedInUsername');
        if (username) {
            loggedInUsernameSpan.textContent = username;
        } else {
            // If not logged in, redirect to login page
            window.location.href = '/';
            return;
        }

        if (addPasskeyButton) {
            addPasskeyButton.addEventListener('click', async () => {
                try {
                    // 1. Request challenge from server
                    const resp = await fetch('/register-passkey-challenge', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username }),
                    });
                    const challengeOptions = await resp.json();

                    if (!resp.ok) {
                        passkeyMessage.textContent = challengeOptions.message || 'Failed to get passkey registration challenge.';
                        passkeyMessage.className = 'message error';
                        return;
                    }

                    // 2. Pass challenge to WebAuthn API
                    const attResp = await SimpleWebAuthnBrowser.startRegistration(challengeOptions);

                    // 3. Send response to server for verification
                    const verificationResp = await fetch('/register-passkey', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ username, attResp }),
                    });
                    const verificationData = await verificationResp.json();

                    if (verificationResp.ok && verificationData.verified) {
                        passkeyMessage.textContent = 'Passkey registered successfully!';
                        passkeyMessage.className = 'message success';
                    } else {
                        passkeyMessage.textContent = verificationData.message || 'Passkey registration failed.';
                        passkeyMessage.className = 'message error';
                    }
                } catch (error) {
                    console.error('Error during passkey registration:', error);
                    passkeyMessage.textContent = 'An error occurred during passkey registration. Please try again.';
                    passkeyMessage.className = 'message error';
                }
            });
        }

        if (logoutButton) {
            logoutButton.addEventListener('click', () => {
                localStorage.removeItem('loggedInUsername');
                window.location.href = '/';
            });
        }
    }
});
