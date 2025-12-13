const API_URL = "http://localhost:8080";

function log(msg) {
    const logEl = document.getElementById('log');
    logEl.textContent = msg + "\n" + logEl.textContent;
    console.log(msg);
}

// ==========================================
// HELPERS: Base64URL <-> ArrayBuffer
// ==========================================
function bufferToBase64URL(buffer) {
    const bytes = new Uint8Array(buffer);
    let string = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        string += String.fromCharCode(bytes[i]);
    }
    return btoa(string)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

function base64URLToBuffer(base64URL) {
    const base64 = base64URL.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - (base64.length % 4)) % 4;
    const padded = base64.padEnd(base64.length + padLen, '=');
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// ==========================================
// 1. Password Registration
// ==========================================
async function registerPassword() {
    const username = document.getElementById('reg-username').value;
    const email = document.getElementById('reg-email').value;
    const password = document.getElementById('reg-password').value;

    try {
        const res = await fetch(`${API_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password })
        });
        const text = await res.text();
        log(`[Password Register] ${res.status}: ${text}`);
    } catch (e) {
        log(`[Error] ${e}`);
    }
}

// ==========================================
// 2. WebAuthn Registration
// ==========================================
async function registerWebAuthn() {
    const username = document.getElementById('webauthn-reg-username').value;
    
    try {
        // Step 1: Start
        log("[WebAuthn] Starting registration...");
        const startRes = await fetch(`${API_URL}/webauthn/register/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        if (!startRes.ok) throw new Error(await startRes.text());
        
        // Returns [req_id, options]
        const [req_id, options] = await startRes.json();
        
        // Convert Challenge & User ID from Base64URL -> Buffer
        options.publicKey.challenge = base64URLToBuffer(options.publicKey.challenge);
        options.publicKey.user.id = base64URLToBuffer(options.publicKey.user.id);

        // Step 2: Browser Prompt
        log("[WebAuthn] Prompting user...");
        const credential = await navigator.credentials.create({ publicKey: options.publicKey });

        // Step 3: Prepare Response for Server
        // We must convert buffers back to Base64URL strings
        const credentialData = {
            id: credential.id,
            rawId: bufferToBase64URL(credential.rawId),
            response: {
                attestationObject: bufferToBase64URL(credential.response.attestationObject),
                clientDataJSON: bufferToBase64URL(credential.response.clientDataJSON)
            },
            type: credential.type
        };

        // Step 4: Finish
        const finishRes = await fetch(`${API_URL}/webauthn/register/finish`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                req_id: req_id, 
                register_response: credentialData 
            })
        });

        const text = await finishRes.text();
        log(`[WebAuthn Register] ${finishRes.status}: ${text}`);

    } catch (e) {
        log(`[Error] ${e.message}`);
    }
}

// ==========================================
// 3. WebAuthn Login
// ==========================================
async function loginWebAuthn() {
    const username = document.getElementById('login-username').value;

    try {
        // Step 1: Start
        log("[WebAuthn] Starting login...");
        const startRes = await fetch(`${API_URL}/webauthn/login/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        if (!startRes.ok) throw new Error(await startRes.text());

        const [req_id, options] = await startRes.json();

        // Convert Challenge & AllowCredentials IDs -> Buffer
        options.publicKey.challenge = base64URLToBuffer(options.publicKey.challenge);
        
        if (options.publicKey.allowCredentials) {
            options.publicKey.allowCredentials.forEach(cred => {
                cred.id = base64URLToBuffer(cred.id);
            });
        }

        // Step 2: Browser Prompt
        log("[WebAuthn] Prompting user...");
        const assertion = await navigator.credentials.get({ publicKey: options.publicKey });

        // Step 3: Prepare Response
        const assertionData = {
            id: assertion.id,
            rawId: bufferToBase64URL(assertion.rawId),
            response: {
                authenticatorData: bufferToBase64URL(assertion.response.authenticatorData),
                clientDataJSON: bufferToBase64URL(assertion.response.clientDataJSON),
                signature: bufferToBase64URL(assertion.response.signature),
                userHandle: assertion.response.userHandle ? bufferToBase64URL(assertion.response.userHandle) : null
            },
            type: assertion.type
        };

        // Step 4: Finish
        const finishRes = await fetch(`${API_URL}/webauthn/login/finish`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                req_id: req_id,
                login_response: assertionData
            })
        });

        const text = await finishRes.text();
        log(`[WebAuthn Login] ${finishRes.status}: ${text}`);

        if (finishRes.ok) {
            const searchParams = new URLSearchParams(window.location.search);
            if (searchParams.has('callback')) {
                const callbackUrl = searchParams.get('callback');
                window.location.href = callbackUrl;
            }
        }

    } catch (e) {
        log(`[Error] ${e.message}`);
    }
}