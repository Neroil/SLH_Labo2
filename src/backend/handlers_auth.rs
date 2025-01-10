//! Gestion des routes nécessitant une authentification utilisateur.

use axum::{
    extract::{Multipart, Query},
    response::{Html, IntoResponse},
    Json, Extension,
};
use anyhow::anyhow;
use handlebars::Handlebars;
use http::StatusCode;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashMap,
    fs::{create_dir_all, File},
    io::Write,
    path::Path,
    sync::{Arc, RwLock},
};
use axum::response::ErrorResponse;
use image::ImageFormat;
use uuid::Uuid;
use validator::Validate;
use crate::consts;
use crate::utils::input::{PostValidation};

/// Modèle représentant un post avec des likes
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Post {
    pub id: Uuid,
    pub content: String,
    pub image_path: Option<String>,
    pub likes: i32,
}

/// Base de données statique pour les posts (simulée en mémoire)
static POSTS: Lazy<RwLock<Vec<Post>>> = Lazy::new(|| {
    RwLock::new(vec![])
});

/// Affiche la page principale avec la liste des posts
pub async fn home(
    Extension(hbs): Extension<Arc<Handlebars<'_>>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let user = params.get("user").cloned().unwrap_or_else(|| "Guest".to_string());
    let data = json!({
        "user": user,
        "posts": *POSTS.read().unwrap(),
    });

    match hbs.render("home", &data) {
        Ok(body) => Html(body),
        Err(_) => Html("<h1>Internal Server Error</h1>".to_string()),
    }
}

/// Crée un nouveau post avec texte et image
pub async fn create_post(mut multipart: Multipart) -> axum::response::Result<Json<serde_json::Value>> {
    let mut text_content = None;
    let mut uploaded_file_path = None;

    while let Some(field) = multipart.next_field().await? {
        let field_name = field.name().unwrap_or_default().to_string();

        if field_name == "text" {
            let text = field.text().await.unwrap_or_default();
            
            let valid_text = PostValidation{
                content: text.to_string(),
            };
            
            valid_text.validate().map_err(|e| {
                ErrorResponse::from((StatusCode::BAD_REQUEST, Json(json!({"error": e.errors()})))
                )
            })?;
            
            text_content = Some(text);
            
        } else if field_name == "file" {
            
            //Valider le content-type
            let content_type = field.content_type()
                .ok_or((StatusCode::BAD_REQUEST, "Content-Type required"))?;
            if !consts::ALLOWED_MIME_TYPES.contains(&content_type) {
                return Err((StatusCode::BAD_REQUEST, "Invalid file type - only JPEG allowed").into());
            }
            
            let filename = field.file_name().unwrap_or_default().to_string();
            let file_bytes = field.bytes().await?;
            
            //Valider la taille du fichier
            if file_bytes.len() > consts::MAX_FILE_SIZE as usize {
                return Err((StatusCode::BAD_REQUEST, "File too large - max 5MB").into());
            }

            //Valider l'image en utilisant crate
            let format = image::guess_format(&file_bytes).map_err(|_| (StatusCode::BAD_REQUEST, "Invalid image format"))?;
            if format != ImageFormat::Jpeg {
                return Err((StatusCode::BAD_REQUEST, "Invalid format - JPEG required").into());
            }

            let uploads_dir = consts::UPLOADS_DIR;
            if !Path::new(uploads_dir).exists() {
                create_dir_all(uploads_dir).unwrap();
            }

            let file_path = format!("{}/{}", uploads_dir, filename);
            let mut file = File::create(&file_path).unwrap();


            file.write_all(&file_bytes).unwrap();

            // Chemin relatif utilisé par le frontend
            uploaded_file_path = Some(format!("{}/{}", consts::UPLOADS_DIR, filename));
        }
    }

    let text = text_content.ok_or((StatusCode::BAD_REQUEST, "Text content is required"))?;

    let valid_text = PostValidation{
        content: text.to_string(),
    };

    valid_text.validate().map_err(|e| {
        ErrorResponse::from((StatusCode::BAD_REQUEST, Json(json!({"error": e.errors()})))
        )
    })?;
    
    let image_path = uploaded_file_path;

    let post_id = save_post(&text, image_path.as_deref());

    Ok(Json(json!({ "post_id": post_id })))
}

/// Sauvegarde des posts dans un fichier YAML
pub fn save_posts_to_file() -> Result<(), anyhow::Error> {
    let posts = POSTS.read().map_err(|_| anyhow!("Failed to read posts"))?; // Lecture des posts existants
    let file_path = consts::POSTS_DB_PATH;
    let file_dir = Path::new(file_path).parent().unwrap();

    if !file_dir.exists() {
        create_dir_all(file_dir).or(Err(anyhow!("Failed to create directory for posts.")))?;
    }

    let file = File::create(file_path).or(Err(anyhow!("Failed to create posts.yaml.")))?;
    serde_yaml::to_writer(file, &*posts).or(Err(anyhow!("Failed to serialize posts to YAML.")))?;
    Ok(())
}

/// Charge les posts depuis un fichier YAML
pub fn load_posts_from_file() -> Result<(), anyhow::Error> {
    let file_path = consts::POSTS_DB_PATH;

    if Path::new(file_path).exists() {
        let file = File::open(file_path).or(Err(anyhow!("Failed to open posts.yaml.")))?;
        let loaded_posts: Vec<Post> = serde_yaml::from_reader(file).unwrap_or_default();

        let mut posts = POSTS.write().map_err(|_| anyhow!("Failed to write posts"))?;
        *posts = loaded_posts;
    }

    Ok(())
}

/// Simule la sauvegarde d'un post dans une base de données
fn save_post(text: &str, image_path: Option<&str>) -> String {
    let new_post = Post {
        id: Uuid::new_v4(),
        content: text.to_string(),
        image_path: image_path.map(|path| path.to_string()),
        likes: 0,
    };

    let post_id = new_post.id.to_string();

    {
        let mut posts = POSTS.write().unwrap();
        posts.push(new_post);
    }

    if let Err(e) = save_posts_to_file() {
        eprintln!("Failed to save posts: {}", e);
    }

    post_id
}

/// Permet de like un post
pub async fn like_post(Json(body): Json<serde_json::Value>) -> axum::response::Result<StatusCode> {
    let post_id = body
        .get("post_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Post ID is required"))?;
    let post_id = Uuid::parse_str(post_id).map_err(|_| (StatusCode::BAD_REQUEST, "Invalid Post ID"))?;

    let action = body
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Action is required"))?;

    let mut posts = POSTS.write().map_err(|_| (StatusCode::BAD_REQUEST, "Failed to write posts"))?;
    let post = posts.iter_mut().find(|post| post.id == post_id);

    if let Some(post) = post {
        match action {
            "like" => {
                if post.likes == 1 {
                    post.likes = 0;
                } else {
                    post.likes = 1;
                }
            }
            "dislike" => {
                if post.likes == -1 {
                    post.likes = 0;
                } else {
                    post.likes = -1;
                }
            }
            _ => return Err((StatusCode::BAD_REQUEST, "Invalid action").into()),
        }
        return Ok(StatusCode::OK);
    }

    Err((StatusCode::NOT_FOUND, "Post not found").into())
}
