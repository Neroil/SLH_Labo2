//! Middleware pour gérer les sessions utilisateur.
//! Vérifie la validité d'une session utilisateur et rejette les requêtes non autorisées.

use axum::extract::FromRequestParts;
use axum::http::{request::Parts, StatusCode};
use tower_sessions::Session;

/// Middleware pour valider une session utilisateur
pub struct SessionUser;

#[async_trait::async_trait]
impl <S> FromRequestParts<S> for SessionUser
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        if let Some(session) = parts.extensions.get::<Session>() {
            if session.get::<bool>("isAuthenticated").unwrap_or_default().is_some() {
                return Ok(SessionUser);
            }
        }

        Err((StatusCode::UNAUTHORIZED, "Unauthorized".to_string()))
    }
}
