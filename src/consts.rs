//! Définition des constantes globales pour l'application.

pub const HTTP_PORT: u16 = 8080; // Port par défaut pour le serveur HTTP.
pub const USERS_DB_PATH: &str = "./data/users.yaml"; // Chemin de la base de données des utilisateurs.
pub const EMAILS_DB_PATH: &str = "./data/emails.yaml"; // Chemin de la base de données des emails.
pub const POSTS_DB_PATH: &str = "./data/posts.yaml"; // Chemin de la base de données des posts.
pub const UPLOADS_DIR: &str = "./data/uploads"; // Dossier pour les fichiers uploadés.
pub const DOMAIN: &str = "localhost"; // Domaine utilisé par le site.
pub const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024; // Taille maximale des fichiers uploadés en octets.
pub const ALLOWED_MIME_TYPES: [&str; 1] = ["image/jpeg"]; // Types MIME autorisés pour les fichiers uploadés.