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

// Validation des fonctions
fn validate_name(username: &str) -> Result<(), ValidationError> {
    let re = Regex::new(r"^[a-zA-ZàáâäãåąčćęèéêëėįìíîïłńòóôöõøùúûüųūÿýżźñçčšžæÀÁÂÄÃÅĄĆČĖĘÈÉÊËÌÍÎÏĮŁŃÒÓÔÖÕØÙÚÛÜŲŪŸÝŻŹÑßÇŒÆČŠŽ∂ð ,.'-]+$").unwrap();
    if !re.is_match(username) {
        return Err(ValidationError::new("name_format_invalid"));
    }
    Ok(())
}

pub(crate) fn validate_description(description: &str) -> Result<(), ValidationError> {
    let re = Regex::new(r"^[\p{L}\p{N}\p{P}\p{Z}]+$").unwrap();
    if !re.is_match(description) {
        return Err(ValidationError::new("description_contains_invalid_chars"));
    }
    Ok(())
}