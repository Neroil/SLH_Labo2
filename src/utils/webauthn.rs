//! Gère l'intégration de WebAuthn pour l'enregistrement, l'authentification, et la récupération.
//! Fournit des fonctions pour démarrer et compléter les processus d'enregistrement et d'authentification.
//! Inclut également des mécanismes pour la gestion sécurisée des passkeys et des tokens de récupération.

use std::collections::HashMap;
use anyhow::{Result, Context};
use webauthn_rs::prelude::*;
use once_cell::sync::Lazy;
use url::Url;
use tokio::sync::RwLock;


// Initialisation globale de WebAuthn
static WEBAUTHN: Lazy<Webauthn> = Lazy::new(|| {
    let rp_id = "localhost";
    let rp_origin = Url::parse("http://localhost:8080").expect("Invalid RP origin URL");

    WebauthnBuilder::new(rp_id, &rp_origin)
        .expect("Failed to initialize WebAuthn")
        .build()
        .expect("Failed to build WebAuthn instance")
});

// Store sécurisé pour les passkeys
pub static CREDENTIAL_STORE: Lazy<RwLock<HashMap<String, Passkey>>> = Lazy::new(Default::default);

// Structure pour stocker l'état d'enregistrement
pub(crate) struct StoredRegistrationState {
    pub registration_state: PasskeyRegistration,
    pub challenge: String,
}

/// Démarrer l'enregistrement WebAuthn
pub async fn begin_registration(
    user_email: &str,
    user_display_name: &str,
) -> Result<(serde_json::Value, PasskeyRegistration)> {
    let user_id = Uuid::new_v4();
    
    let (ccr,reg_state) = WEBAUTHN.start_passkey_registration(
        user_id,
        user_email,
        user_display_name,
        None,
    ).expect("Failed to start registration.");

    let public_key = ccr.public_key;

    Ok((
        serde_json::json!({
            "rp": public_key.rp,
            "user": {
                "id": user_id,
                "name": user_display_name,
                "displayName": user_display_name,
            },
            "challenge": public_key.challenge,
            "pubKeyCredParams": public_key,
            "timeout": public_key.timeout,
            "authenticatorSelection": public_key.authenticator_selection,
            "attestation": public_key.attestation,
        }),
        reg_state,
    ))
}

/// Compléter l'enregistrement WebAuthn
pub async fn complete_registration(
    user_email: &str,
    response: &RegisterPublicKeyCredential,
    stored_state: &StoredRegistrationState,
) -> Result<()> {

    // TODO
    let passkey = WEBAUTHN.finish_passkey_registration(
        response,
        &stored_state.registration_state,
    ).context("Failed to finish registration")?;

    let mut store = CREDENTIAL_STORE.write().await;
    store.insert(user_email.to_string(), passkey);

    Ok(())
}

/// Démarrer l'authentification WebAuthn
pub async fn begin_authentication(user_email: &str) -> Result<(serde_json::Value, PasskeyAuthentication)> {

    let store = CREDENTIAL_STORE.read().await;
    let passkey = store.get(user_email).context("User not found")?;


    // TODO
    let (rcr,passkey_auth) = WEBAUTHN.start_passkey_authentication(
        std::slice::from_ref(passkey)
    ).context("Failed to start authentication")?;

    let public_key = rcr.public_key;

    Ok((
        serde_json::json!({
            "challenge": public_key.challenge,
            "timeout": public_key.timeout,
            "rpId": public_key.rp_id,
            "allowCredentials": public_key.allow_credentials,
         }),
        passkey_auth,
    ))
}

/// Compléter l'authentification WebAuthn
pub async fn complete_authentication(
    response: &PublicKeyCredential,
    state: &PasskeyAuthentication,
    server_challenge: &str,
) -> Result<()> {
    let client_data_bytes = response.response.client_data_json.as_ref();
    let client_data_json = String::from_utf8(client_data_bytes.to_vec())
        .context("Failed to decode client_data_json")?;

    let client_data: serde_json::Value = serde_json::from_str(&client_data_json)
        .context("Failed to parse client_data_json")?;

    // TODO

    // Vérification du challenge
    let challenge = client_data.get("challenge")
        .and_then(|c| c.as_str())
        .context("Missing challenge")?;

    if challenge != server_challenge {
        return Err(anyhow::anyhow!("Invalid challenge"));
    }


    WEBAUTHN.finish_passkey_authentication(
        response,
        state
    ).context("Failed to finish authentication")?;

    Ok(())
}
