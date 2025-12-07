const API = "http://127.0.0.1:8080";

// -----------------------------------------------------
// HELPER FUNCTIONS
// -----------------------------------------------------

const postJSON = async (url, data) => {
    return fetch(API + url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    }).then(res => res.json());
};

function base64urlToBuffer(base64url) {
    const padding = "=".repeat((4 - base64url.length % 4) % 4);
    const base64 = (base64url + padding)
        .replace(/-/g, "+")
        .replace(/_/g, "/");
    const str = atob(base64);
    const bytes = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
    return bytes.buffer;
}

function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = "";
    for (const byte of bytes) str += String.fromCharCode(byte);
    const base64 = btoa(str);
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// -----------------------------------------------------
// PASSWORD LOGIN
// -----------------------------------------------------
async function loginUser() {
    const username = document.getElementById("login_username").value;
    const password = document.getElementById("login_password").value;

    const res = await postJSON("/login", { username, password });
    console.log("LOGIN:", res);

    if (res.error) {
        alert("Login failed: " + res.error);
        return;
    }
}


// -----------------------------------------------------
// USER REGISTRATION FLOW
// -----------------------------------------------------
async function registerUser() {
    const username = document.getElementById("reg_username").value;
    const email = document.getElementById("reg_email").value;
    const password = document.getElementById("reg_password").value;

    // 1. Create password user in DB
    const reg = await postJSON("/register", { username, email, password });
    console.log("REGISTER:", reg);

    if (reg.error) {
        alert(reg.error);
        return;
    }

    // 2. Begin WebAuthn registration
    const start = await postJSON("/webauthn/start", {
        username,
        mode: "register"
    });

    console.log("WEBAUTHN START:", start);

    // Convert base64 → ArrayBuffer
    start.publicKey.challenge = base64urlToBuffer(start.publicKey.challenge);
    start.publicKey.user.id  = base64urlToBuffer(start.publicKey.user.id);

    // 3. Create credentials using browser
    const cred = await navigator.credentials.create(start);

    console.log("CREDENTIAL:", cred);

    // 4. Send credential response to backend (finish)
    const finish = await postJSON("/webauthn/finish", {
        username,
        mode: "register",
        credential: {
            id: cred.id,
            rawId: bufferToBase64url(cred.rawId),
            type: cred.type,
            response: {
                attestationObject: bufferToBase64url(cred.response.attestationObject),
                clientDataJSON: bufferToBase64url(cred.response.clientDataJSON)
            }
        }
    });

    console.log("WEBAUTHN FINISH:", finish);
}




// -----------------------------------------------------
// WEBAUTHN LOGIN FLOW
// -----------------------------------------------------
async function loginWebAuthn() {
    const username = document.getElementById("login_username").value;

    // 1. Start WebAuthn login
    const start = await postJSON("/webauthn/start", { username, mode: "login" });
    console.log("WEBAUTHN LOGIN START:", start);

    if (start.error) {
        alert("WebAuthn login failed: " + start.error);
        return;
    }

    // --- 2. Convert options from server ---
    const publicKey = {
        ...start.publicKey,
        challenge: base64urlToBuffer(start.publicKey.challenge),
        allowCredentials: start.publicKey.allowCredentials.map(c => ({
            ...c,
            id: base64urlToBuffer(c.id),
        })),
    };

    // --- 3. Call WebAuthn authenticator ---
    let assertion;
    try {
        assertion = await navigator.credentials.get({ publicKey });
    } catch (err) {
        console.error("WebAuthn get() failed:", err);
        alert("Authentication canceled.");
        return;
    }

    console.log("ASSERTION:", assertion);

    // --- 4. Send response back to Rust to verify ---
    const finish = await postJSON("/webauthn/finish", {
        username,
        credential: {
            id: assertion.id,
            rawId: bufferToBase64url(assertion.rawId),
            type: assertion.type,
            response: {
                clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
                authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
                signature: bufferToBase64url(assertion.response.signature),
                userHandle: assertion.response.userHandle
                    ? bufferToBase64url(assertion.response.userHandle)
                    : null
            }
        }
    });

    console.log("WEBAUTHN LOGIN FINISH:", finish);

    if (finish.error) {
        alert("WebAuthn login failed: " + finish.error);
    } else {
        alert("WebAuthn login successful!");
        // Do your login redirect, store token, etc.
    }
}
