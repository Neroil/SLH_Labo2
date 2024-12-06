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
    let user_id = todo!();


    // TODO

    Ok((
        serde_json::json!({
            "rp": todo!(),
            "user": {
                "id": todo!(),
                "name": todo!(),
                "displayName": todo!(),
            },
            "challenge": todo!(),
            "pubKeyCredParams": todo!(),
            "timeout": todo!(),
            "authenticatorSelection": todo!(),
            "attestation": todo!(),
        }),
        todo!(),
    ))
}

/// Compléter l'enregistrement WebAuthn
pub async fn complete_registration(
    user_email: &str,
    response: &RegisterPublicKeyCredential,
    stored_state: &StoredRegistrationState,
) -> Result<()> {

    // TODO

    Ok(())
}

/// Démarrer l'authentification WebAuthn
pub async fn begin_authentication(user_email: &str) -> Result<(serde_json::Value, PasskeyAuthentication)> {

    // TODO

    Ok((
        serde_json::json!({
            "challenge": todo!(),
            "timeout": todo!(),
            "rpId": todo!(),
            "allowCredentials": todo!(),
         }),
        todo!(),
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

    Ok(())
}
