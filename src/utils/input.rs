use regex::Regex;
use serde::Deserialize;
use validator::{Validate, ValidationError};

#[derive(Debug, Deserialize, Validate)]
pub struct UserRegistration {
    #[validate(length(min = 1, max = 50))]
    #[validate(custom(function= "validate_name"))]
    pub first_name: String,
    
    #[validate(length(min = 1, max = 50))]
    #[validate(custom(function= "validate_name"))]
    pub last_name: String,

    #[validate(email)]
    pub email: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct MailValidation {
    #[validate(email)]
    pub email: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct PostValidation {
    #[validate(length(min = 1, max = 500))]
    #[validate(custom(function= "validate_description"))]
    pub content: String,
}

// Validation des noms prenant en charge les caractères spéciaux et les accents.
fn validate_name(username: &str) -> Result<(), ValidationError> {
    let re = Regex::new(r"^[a-zA-ZàáâäãåąčćęèéêëėįìíîïłńòóôöõøùúûüųūÿýżźñçčšžæÀÁÂÄÃÅĄĆČĖĘÈÉÊËÌÍÎÏĮŁŃÒÓÔÖÕØÙÚÛÜŲŪŸÝŻŹÑßÇŒÆČŠŽ∂ð ,.'-]+$").unwrap();
    if !re.is_match(username) {
        return Err(ValidationError::new("name_format_invalid"));
    }
    Ok(())
}

// Validation de la description des posts en enlevant tout ce qui n'est pas des lettres, des chiffres, des espaces, ou des ponctuations.
pub(crate) fn validate_description(description: &str) -> Result<(), ValidationError> {
    let re = Regex::new(r"^[\p{L}\p{N}\p{P}\p{Z}\n]+$").unwrap();

    if !re.is_match(description) {
        return Err(ValidationError::new("description_contains_invalid_chars"));
    }
    Ok(())
}

//Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_name() {
        // Tests valides
        assert!(validate_name("Jean").is_ok());
        assert!(validate_name("Marie-Anne").is_ok());
        assert!(validate_name("François").is_ok());
        assert!(validate_name("Jean-François").is_ok());
        assert!(validate_name("O'Connor").is_ok());
        assert!(validate_name("von der Leyen").is_ok());
        assert!(validate_name("José María").is_ok());

        // Tests invalides
        assert!(validate_name("Jean123").is_err());
        assert!(validate_name("Marie@Anne").is_err());
        assert!(validate_name("François!").is_err());
        assert!(validate_name("Jean#François").is_err());
        assert!(validate_name("123").is_err());
        assert!(validate_name("").is_err());
        assert!(validate_name("@#$%").is_err());
    }

    #[test]
    fn test_validate_description() {
        // Tests valides
        assert!(validate_description("Ceci est une description normale.").is_ok());
        assert!(validate_description("Description avec des chiffres 123 et ponctuation!").is_ok());
        assert!(validate_description("Multi-lignes\navec des sauts\net ponctuation...").is_ok());

        // Tests invalides
        assert!(validate_description("").is_err()); // Vide
        assert!(validate_description("\u{0000}").is_err()); // Caractère null
        assert!(validate_description("Texte avec des <script>alert('Coucou les assistants')</script> injections").is_err());
    }

    #[test]
    fn test_user_registration_validation() {
        let valid_user = UserRegistration {
            first_name: "Jean".to_string(),
            last_name: "Dupont".to_string(),
            email: "jean.dupont@example.com".to_string(),
        };
        assert!(valid_user.validate().is_ok());

        let invalid_user = UserRegistration {
            first_name: "Jean123".to_string(),
            last_name: "Dupont!".to_string(),
            email: "invalid-email".to_string(),
        };
        assert!(invalid_user.validate().is_err());
    }

    #[test]
    fn test_mail_validation() {
        let valid_mail = MailValidation {
            email: "test@example.com".to_string(),
        };
        assert!(valid_mail.validate().is_ok());

        let invalid_mail = MailValidation {
            email: "invalid-email".to_string(),
        };
        assert!(invalid_mail.validate().is_err());
    }

    #[test]
    fn test_post_validation() {
        let valid_post = PostValidation {
            content: "Ceci est un contenu valide.".to_string(),
        };
        assert!(valid_post.validate().is_ok());

        let invalid_post = PostValidation {
            content: "".to_string(), // Trop court
        };
        assert!(invalid_post.validate().is_err());

        let too_long_post = PostValidation {
            content: "a".repeat(501), // Trop long
        };
        assert!(too_long_post.validate().is_err());
    }
}