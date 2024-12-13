//! Gestion des routes accessibles sans authentification.
//! Contient les handlers pour les pages publiques, l'inscription, la connexion,
//! la récupération de compte et la validation d'utilisateur.

use axum::{
    extract::{Json, Path, Query}, http::StatusCode, response::{ErrorResponse, Html, IntoResponse, Redirect}
};

use once_cell::sync::Lazy;
use crate::email::{self, send_mail};
use serde_json::json;
use std::collections::HashMap;
use tokio::sync::RwLock;
use webauthn_rs::prelude::{PasskeyAuthentication, PublicKeyCredential, RegisterPublicKeyCredential};
use crate::HBS;
use crate::database::{user, token};
use crate::utils::webauthn::{begin_registration, complete_registration, begin_authentication, complete_authentication, StoredRegistrationState, CREDENTIAL_STORE};

/// Structure pour gérer un état temporaire avec un challenge
struct TimedStoredState<T> {
    state: T,
    server_challenge: String,
}

/// Stockage des états d'enregistrement et d'authentification
pub(crate) static REGISTRATION_STATES: Lazy<RwLock<HashMap<String, StoredRegistrationState>>> =
    Lazy::new(Default::default);
static AUTHENTICATION_STATES: Lazy<RwLock<HashMap<String, TimedStoredState<PasskeyAuthentication>>>> = Lazy::new(Default::default);

/// Début du processus d'enregistrement WebAuthn
pub async fn register_begin(Json(payload): Json<serde_json::Value>) -> axum::response::Result<Json<serde_json::Value>> {

    let email = payload
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "Email is required"))?;

    let reset_mode = payload.get("reset_mode").and_then(|v| v.as_bool()).unwrap_or(false);


    // TODO
    // Vérifier si l'utilisateur existe déjà (sauf en mode reset)
    if !reset_mode {
        if user::exists(email).unwrap_or(false) {
           return Err(ErrorResponse::from("User already exists"));
        }
    }
    
    let (public_key, reg_state) = begin_registration(email, email)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let state_id = uuid::Uuid::new_v4().to_string();

    let mut states = REGISTRATION_STATES.write().await;
    states.insert(state_id.clone(), StoredRegistrationState {
        registration_state: reg_state,
        challenge: public_key["challenge"].as_str().unwrap().to_string(),
    });

    Ok(Json(json!({
        "publicKey": public_key,
        "state_id": state_id,
    })))
}

/// Fin du processus d'enregistrement WebAuthn
pub async fn register_complete(Json(payload): Json<serde_json::Value>) -> axum::response::Result<StatusCode> {

    let email = payload
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "Email is required"))?;

    let reset_mode = payload.get("reset_mode").and_then(|v| v.as_bool()).unwrap_or(false);

    let first_name = payload
        .get("first_name")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "First name is required"))?;
    let last_name = payload
        .get("last_name")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "Last name is required"))?;

    // TODO

    // 1. Récupérer l'état d'enregistrement
    let state_id = payload.get("state_id")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "State ID is required"))?;

    let mut states = REGISTRATION_STATES.write().await;
    let stored_state = states.remove(state_id)
        .ok_or((StatusCode::BAD_REQUEST, "Invalid state"))?;

    // 2. Convertir la réponse en RegisterPublicKeyCredential
    let response: RegisterPublicKeyCredential = serde_json::from_value(
        payload
            .get("response")
            .ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    "Response is required".to_string(),
                )
            })?
            .clone(),
    ).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid response format: {}", err),
        )
    })?;

    // 3. Compléter l'enregistrement
    complete_registration(email, &response, &stored_state).await.map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to complete registration: {}", err),
        )
    })?;

    // 4. Créer ou mettre à jour l'utilisateur en base de données
    user::create(email, first_name, last_name).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create user: {}", err),
        )
    })?;

    // Envoyer email de validation si nécessaire
    

    Ok(StatusCode::OK)
}

/// Début du processus d'authentification WebAuthn
pub async fn login_begin(Json(payload): Json<serde_json::Value>) -> axum::response::Result<Json<serde_json::Value>> {
    let email = payload
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "Email is required"))?;

    // TODO
    
    // Vérifier si l'utilisateur existe
    if !user::exists(email).unwrap_or(false) {
        return Err(ErrorResponse::from("User not found"));
    }

    // Débuter l'authentification
    let (public_key, auth_state) = begin_authentication(email)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let state_id = uuid::Uuid::new_v4().to_string();

    // Stocker l'état d'authentification
    let mut states = AUTHENTICATION_STATES.write().await;
    states.insert(state_id.clone(), TimedStoredState {
        state: auth_state,
        server_challenge: public_key["challenge"].as_str().unwrap().to_string(),
    });

    Ok(Json(json!({
        "publicKey": public_key,
        "state_id": state_id,
    })))
}

/// Fin du processus d'authentification WebAuthn
pub async fn login_complete(Json(payload): Json<serde_json::Value>) -> axum::response::Result<Redirect> {
    let response = payload.get("response").ok_or_else(|| (StatusCode::BAD_REQUEST, "Response is required"))?;
    let state_id = payload.get("state_id").and_then(|v| v.as_str()).ok_or_else(|| (StatusCode::BAD_REQUEST, "State ID is required"))?;

    // TODO
    // Récupérer l'état d'authentification
    let mut states = AUTHENTICATION_STATES.write().await;
    let stored_state = states.remove(state_id)
        .ok_or((StatusCode::BAD_REQUEST, "Invalid state"))?;

    // Convertir la réponse
    let credential: PublicKeyCredential = serde_json::from_value(response.clone())
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid response format"))?;

    // Compléter l'authentification
    complete_authentication(&credential, &stored_state.state, &stored_state.server_challenge)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;

    // TODO: Créer une session pour l'utilisateur authentifié
    // session.insert("email", email).await?;

    Ok(Redirect::to("/home"))
}

/// Gère la déconnexion de l'utilisateur
pub async fn logout() -> impl IntoResponse {
    Redirect::to("/")
}

/// Valide un compte utilisateur via un token
pub async fn validate_account(Path(token): Path<String>) -> impl IntoResponse {
    match token::consume(&token) {
        Ok(email) => match user::verify(&email) {
            Ok(_) => Redirect::to("/login?validated=true"),
            Err(_) => Redirect::to("/register?error=validation_failed"),
        },
        Err(_) => Redirect::to("/register?error=invalid_token"),
    }
}

/// Envoie un email de récupération de compte à l'utilisateur
pub async fn recover_account(Json(payload): Json<serde_json::Value>) -> axum::response::Result<Html<String>> {
    let mut data = HashMap::new();

    // TODO : Utilisez la fonction send_email
    let email = payload
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "Email is required"))?;

    // Vérifier si l'utilisateur existe
    if !user::exists(email).unwrap_or(false) {
        return Err(ErrorResponse::from("User not found"));
    }

    // Générer un token de récupération
    let recovery_token = token::generate(email).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create recovery token")
    })?;

    // Envoyer l'email de récupération
    // TODO: Implémenter l'envoi d'email avec le lien de récupération
    email::send_mail(email, "Account Recovery", &format!("Click here to recover your account: http://localhost:3000/reset/{}", recovery_token))
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to send recovery email"))?;

    data.insert("message", "Recovery email sent. Please check your inbox.");

    HBS.render("recover", &data)
        .map(Html)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error.").into())
}

/// Gère la réinitialisation du compte utilisateur via un token de récupération
pub async fn reset_account(Path(token): Path<String>) -> Html<String> {
    match token::consume(&token) {
        Ok(email) => {
            let redirect_url = format!("/register?reset_mode=true&email={}&success=true", email);
            Html(format!("<meta http-equiv='refresh' content='0;url={}'/>", redirect_url))
        }
        Err(_) => {
            let redirect_url = "/register?error=recovery_failed";
            Html(format!("<meta http-equiv='refresh' content='0;url={}'/>", redirect_url))
        }
    }
}

/// --- Affichage des pages ---
///
/// Affiche la page d'accueil
pub async fn index(session: tower_sessions::Session) -> impl IntoResponse {
    let is_logged_in = session.get::<String>("email").is_ok();
    let mut data = HashMap::new();
    data.insert("logged_in", is_logged_in);

    HBS.render("index", &data)
        .map(Html)
        .unwrap_or_else(|_| Html("Internal Server Error".to_string()))
}

/// Affiche la page de connexion
pub async fn login_page() -> impl IntoResponse {
    Html(include_str!("../../templates/login.hbs"))
}

/// Affiche la page d'inscription avec des messages contextuels si présents
pub async fn register_page(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let mut context = HashMap::new();
    if let Some(success) = params.get("success") {
        if success == "true" {
            context.insert("success_message", "Account recovery successful. Please reset your passkey.");
        }
    }
    if let Some(error) = params.get("error") {
        if error == "recovery_failed" {
            context.insert("error_message", "Invalid or expired recovery link. Please try again.");
        }
    }

    HBS.render("register", &context)
        .map(Html)
        .unwrap_or_else(|_| Html("<h1>Internal Server Error</h1>".to_string()))
}

/// Affiche la page de récupération de compte
pub async fn recover_page() -> impl IntoResponse {
    Html(include_str!("../../templates/recover.hbs"))
}
