const API = "http://127.0.0.1:8080";

const postJSON = async (url, data) => {
    return fetch(API + url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    }).then(res => res.json());
};

// -----------------------------------------------------
// USER REGISTRATION FLOW
// -----------------------------------------------------
async function registerUser() {
    const username = document.getElementById("reg_username").value;
    const email = document.getElementById("reg_email").value;
    const password = document.getElementById("reg_password").value;

    // 1. Create password user
    const reg = await postJSON("/register", { username, email, password });
    console.log("REGISTER:", reg);

    if (reg.error) {
        alert(reg.error);
        return;
    }

    // 2. Begin WebAuthn registration
    const start = await postJSON("/webauthn/start", { username, mode: "register" });
    console.log("WEBAUTHN START:", start);
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

    //alert("Logged in (Password)");
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

}
