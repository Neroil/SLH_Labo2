//! Gestion des routes accessibles sans authentification.
//! Contient les handlers pour les pages publiques, l'inscription, la connexion,
//! la récupération de compte et la validation d'utilisateur.

use axum::{
    extract::{Json, Path, Query}, http::StatusCode, response::{ErrorResponse, Html, IntoResponse, Redirect}
};

use once_cell::sync::Lazy;
use tower_sessions::Session;
use crate::email::{self, send_mail};
use serde_json::json;
use std::collections::HashMap;
use tokio::sync::RwLock;
use validator::{Validate, ValidationError};
use webauthn_rs::prelude::{PasskeyAuthentication, PublicKeyCredential, RegisterPublicKeyCredential};
use crate::HBS;
use crate::database::{user, token};
use crate::utils::webauthn::{begin_registration, complete_registration, begin_authentication, complete_authentication, StoredRegistrationState, CREDENTIAL_STORE};


//Validation des emails 

#[derive(Debug, Validate)]
struct EmailInput {
    #[validate(email)]
    email: String,
}

impl EmailInput {
    pub fn new(email: &str) -> Option<Self> {
        let instance = EmailInput {
            email: email.to_string(),
        };
        if instance.validate().is_ok() {
            Some(instance)
        } else {
            None
        }
    }
}


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


    //Validate the email 
    let validated_email =  EmailInput::new(email).ok_or((StatusCode::BAD_REQUEST, "Email is Invalid !"))?;

    // TODO
    // Vérifier si l'utilisateur existe déjà (sauf en mode reset)
    if !reset_mode {
        if user::exists(&validated_email.email).unwrap_or(false) {
           return Err(ErrorResponse::from("User already exists"));
        }
    }
    
    //Begin registration
    let (public_key, reg_state) = begin_registration(email, email)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    //Unique ID for this registration
    let state_id = uuid::Uuid::new_v4().to_string();

    //Write to the DB
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
// Extraire et valider l'email
let email = payload
.get("email")
.and_then(|v| v.as_str())
.ok_or((StatusCode::BAD_REQUEST, "Email is required"))?;

let validated_email = EmailInput::new(email)
.ok_or((StatusCode::BAD_REQUEST, "Email is Invalid!"))?;

// Extraire les autres champs requis
let first_name = payload
.get("first_name")
.and_then(|v| v.as_str())
.ok_or((StatusCode::BAD_REQUEST, "First name is required"))?;

let last_name = payload
.get("last_name")
.and_then(|v| v.as_str())
.ok_or((StatusCode::BAD_REQUEST, "Last name is required"))?;

// Récupérer l'état d'enregistrement
let state_id = payload
.get("state_id")
.and_then(|v| v.as_str())
.ok_or((StatusCode::BAD_REQUEST, "State ID is required"))?;

let mut states = REGISTRATION_STATES.write().await;
let stored_state = states
.remove(state_id)
.ok_or((StatusCode::BAD_REQUEST, "Invalid state"))?;

// Convertir et valider la réponse WebAuthn
let response: RegisterPublicKeyCredential = serde_json::from_value(
payload
    .get("response")
    .ok_or((StatusCode::BAD_REQUEST, "Response is required"))?
    .clone(),
).map_err(|err| (StatusCode::BAD_REQUEST, format!("Invalid response format: {}", err)))?;

// Compléter l'enregistrement WebAuthn
complete_registration(email, &response, &stored_state)
.await
.map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to complete registration: {}", err)))?;

// Récupérer la passkey générée
let passkey = CREDENTIAL_STORE
.read()
.await
.get(email)
.ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Passkey not found"))?
.clone();

// Créer l'utilisateur en base de données
user::create(email, first_name, last_name)
.map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create user: {}", err)))?;

// Associer la passkey à l'utilisateur
user::set_passkey(email, passkey)
.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to set passkey"))?;

// Générer et envoyer le token de validation par email
let validation_token = token::generate(email)
.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate validation token"))?;

// Construire le message de validation
let validation_url = format!("http://localhost:3000/validate/{}", validation_token);
let email_body = format!(
"Welcome! Please click the following link to validate your account: {}",
validation_url
);

// Envoyer l'email de validation
send_mail(email, "Account Validation", &email_body)
.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to send validation email"))?;

Ok(StatusCode::OK)
}

/// Début du processus d'authentification WebAuthn
pub async fn login_begin(Json(payload): Json<serde_json::Value>) -> axum::response::Result<Json<serde_json::Value>> {
    let email = payload
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "Email is required"))?;

        //TODO
    // Validate email first
    let validated_email = EmailInput::new(email)
        .ok_or((StatusCode::BAD_REQUEST, "Email is Invalid!"))?;

    // Check if user exists
    if !user::exists(&validated_email.email).unwrap_or(false) {
        return Err(ErrorResponse::from("User not found"));
    }

    // Begin authentication using the validated email
    let (public_key, auth_state) = begin_authentication(&validated_email.email)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let state_id = uuid::Uuid::new_v4().to_string();

    // Store authentication state with email
    let mut states = AUTHENTICATION_STATES.write().await;
    states.insert(state_id.clone(), TimedStoredState {
        state: auth_state,
        server_challenge: public_key["challenge"].as_str().unwrap().to_string(),
    });

    // Return both the public key and state ID
    Ok(Json(json!({
        "publicKey": public_key,
        "state_id": state_id,
    })))
}

/// Fin du processus d'authentification WebAuthn
pub async fn login_complete(
    session: Session,
    Json(payload): Json<serde_json::Value>) -> axum::response::Result<Redirect> {
    let email = payload
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "Email is required"))?;
    
    let response = payload
        .get("response")
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Response is required"))?;
        
    let state_id = payload
        .get("state_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "State ID is required"))?;

    // Get stored state
    let mut states = AUTHENTICATION_STATES.write().await;
    let stored_state = states
        .remove(state_id)
        .ok_or((StatusCode::BAD_REQUEST, "Invalid state"))?;

    // Convert the response
    let credential: PublicKeyCredential = serde_json::from_value(response.clone())
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid response format"))?;

    // Complete authentication
    complete_authentication(&credential, &stored_state.state, &stored_state.server_challenge)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;

    // Create session
    // TODO: Implement proper session management
    //session.insert("email", email).await?;
    session
        .insert("isAuthenticated", true)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to set session"))?;


    Ok(Redirect::to("/home"))
}

/// Gère la déconnexion de l'utilisateur
pub async fn logout(
    session: Session,
) -> impl IntoResponse {
    session.delete();
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

    //TODO FIX THIS OMG
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
