/* To be able to return Templates */
use std::{
    collections::HashMap,
    env,
    ops::Add, usize
};

/* Diesel query builder */
use diesel::prelude::*;

/* To be able to parse raw forms */
use rocket::{
    Data, get, post,
    http::ContentType,
    request::FlashMessage,
    response::{ 
        Flash, Redirect
    },
    // tokio::fs 
};

use cookie::{ Cookie, CookieJar, Key };

use rocket_dyn_templates::Template;

use rocket_multipart_form_data::{
    MultipartFormData,
    MultipartFormDataField,
    MultipartFormDataOptions,
};

use serde::{ Serialize, Deserialize };   

use chrono::{ 
    self,
    NaiveDateTime,
    DateTime,
    Local,
    Duration
};

use time::{ OffsetDateTime, macros::offset };

use crate::{
    models::{ User, NewUser },
    schema::*,
    establish_connection
};

use jsonwebtoken::{ 
    encode, EncodingKey, Header, 
    // errors::ErrorKind, decode, DecodingKey, Validation,
};

use once_cell::sync::Lazy;
use std::sync::RwLock;

use pbkdf2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHasher, SaltString,
        PasswordHash, PasswordVerifier
    },
    Pbkdf2
};




#[get("/")]
pub fn index(
    flash: Option<FlashMessage>
) -> Template {
    let mut context = HashMap::new();
    if let Some(ref flash_message) = flash {
        context.insert("flash", flash_message.message());
    }



    Template::render("index", context)
}

#[get("/register")]
pub fn new_user(flash: Option<FlashMessage>) -> Template {
    let mut context = HashMap::new();
    if let Some(ref flash) = flash {
        context.insert("flash", flash.message());
    }
    Template::render("register", context)
}

#[post("/register", data = "<user_data>")]
pub async fn process_user(
    content_type: &ContentType, 
    user_data: Data<'_>
) -> Flash<Redirect> {
    let mut conn = establish_connection();

    /* First we declare what we will be accepting on this form */
    let mut options = MultipartFormDataOptions::new();

    options.allowed_fields = vec![
        MultipartFormDataField::text("email"),
        MultipartFormDataField::text("username"),
        MultipartFormDataField::text("password"),
        MultipartFormDataField::text("password_confirm"),
    ];

    let salt = SaltString::generate(&mut OsRng);

    /* If stuff matches, do stuff */
    let multipart_form_data = MultipartFormData::parse(content_type, user_data, options).await;

    match multipart_form_data {
        Ok(form) => {
            let username = form.texts.get("username").unwrap()[0].text.clone();
            let password = form.texts.get("password").unwrap()[0].text.clone();
            let hash: PasswordHash = Pbkdf2.hash_password(&password.as_bytes(), &salt).unwrap();
            let password_hash = hash.to_string();

            let dt: DateTime<Local> = Local::now();
            let naive_utc: NaiveDateTime = dt.naive_utc();

            /* Insert our form data inside our database */
            let insert = diesel::insert_into(users::table)
                .values(NewUser {
                    email: match form.texts.get("email") {
                        Some(value) => &value[0].text,
                        None => "New",
                    },
                    username: &username,
                    password: &password_hash,
                    tier: 1,
                    admin: false,
                    full_name: None,
                    created_at: naive_utc,
                    updated_at: naive_utc,
                    deleted_at: None,
                })
                .execute(&mut conn);
            
            match insert {
                Ok(_) => {
                    let user = users::table
                        .filter(users::username.eq(&username))
                        .limit(1)
                        .get_result::<User>(&mut conn)
                        .expect("Error loading users");
                
                    let user_id  = &user.id.to_string();

                    let user_claims = UserClaims { 
                        username: username.clone(),
                        sub: user_id.to_string().clone(),
                        exp: (chrono::Utc::now() + chrono::Duration::days(1)).timestamp() as i64,
                    };

                    let token = create_token(&username, &user_id);

                    // Create and add the cookie
                    create_and_add_cookie(&token, &user_claims);

                    Flash::success(
                        Redirect::to(format!("/dashboard/{}", username)),
                        "Success! You are accepting into our database as a new Rooster",
                    )
                },
                Err(err_msg) => Flash::error(
                    Redirect::to("/register"),
                    format!(
                        "Houston, We had problems while inserting things into our database ... {}",
                        err_msg
                    ),
                ),
            }
        }
        Err(err_msg) => {
                /* Falls to this patter if theres some fields that isn't allowed or bolsonaro rules this code */
            Flash::error(
                Redirect::to("/register"),
                format!(
                    "Houston, We have problems parsing our form... Debug info: {}",
                    err_msg
                ),
            )
        }
    }
}

#[get("/login")]
pub fn login(flash: Option<FlashMessage>) -> Template {
    let mut context = HashMap::new();

    if let Some(ref flash) = flash {
        context.insert("flash", flash.message());
    }

    Template::render("login", &context)
}

#[post("/login", data = "<user_data>")]
pub async fn process_login(
    content_type: &ContentType, 
    user_data: Data<'_>
) -> Result<Redirect, Flash<Redirect>> {
    let mut context = HashMap::new();
    let mut conn = establish_connection();

    // Validate user credentials
    
    /* First we declare what we will be accepting on this form */
    let mut options = MultipartFormDataOptions::new();

    options.allowed_fields = vec![
        MultipartFormDataField::text("username"),
        MultipartFormDataField::text("password"),
    ];

    /* If stuff matches, do stuff */
    let multipart_form_data = MultipartFormData::parse(content_type, user_data, options).await.unwrap();
    
    let username = &multipart_form_data.texts.get("username").unwrap()[0].text.clone();
    let password = &multipart_form_data.texts.get("password").unwrap()[0].text.clone();

    context.insert("username", &username);

    let user_table: Vec<User> = users::table
        .filter(users::username.eq(&username))
        .limit(1)
        .load::<User>(&mut conn)
        .expect("Error loading users");
    
    let user = user_table.first().unwrap();
    
    let user_id  = &user.id.to_string();
    let stored_password = &user.password;

    if verify_password(stored_password, password) {
        let user_claims = UserClaims { 
            username: username.clone(),
            sub: user_id.clone(),
            exp: (chrono::Utc::now() + chrono::Duration::days(1)).timestamp() as i64,
        };

        let token = create_token(username, user_id);

        // Create and add the cookie
        create_and_add_cookie(&token, &user_claims);

        // Store the new_jar in the request's metadata
        // request.cookies().add_private(jar);

        Ok(Redirect::to(format!("/dashboard/{}", username)))
    } else {
        Err(Flash::error(
                Redirect::to("/login"),
                "Invalid username or password"
        ))
    }
}








pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Pbkdf2.hash_password(password.as_bytes(), &salt);
    hash.unwrap().to_string()
}

pub fn verify_password(hash: &str, password: &str) -> bool {
    let parsed_hash = PasswordHash::new(hash).unwrap();
    Pbkdf2.verify_password(password.as_bytes(), &parsed_hash).is_ok()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserClaims {
    pub username: String,
    pub sub: String,
    pub exp: i64,
}

impl Default for UserClaims {
    fn default() -> Self {
        UserClaims {
            username: "USERNAME".to_string(),
            sub: "-1".to_string(),
            exp: Local::now().naive_utc().and_utc().timestamp(),
        }
    }
}

static SECRET_KEY: Lazy<String> = Lazy::new(|| {
    env::var("SECRET_KEY").unwrap_or_else(|_| "default-secret-key".to_string()).to_string().to_owned()
});

pub fn get_secret_key() -> String {
    SECRET_KEY.to_string()
}

static COOKIE_KEY: Lazy<Key> = Lazy::new(|| {
    Key::generate()
});

pub fn get_cookie_key() -> Key {
    COOKIE_KEY.to_owned()
}

pub static COOKIE_JAR: RwLock<Option<CookieJar>> = RwLock::new(None);

pub fn get_cookie_jar() -> Option<CookieJar> {
    let cookie_jar = COOKIE_JAR.read().unwrap();
    cookie_jar.clone()
}

pub fn create_token(username: &str, user_id: &str) -> String {
    let now = DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    let expiration = now.add(Duration::hours(1)).timestamp_millis(); // Set a suitable expiration time
    let claims = UserClaims { username: username.to_owned(), sub: user_id.to_owned(), exp: expiration };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(SECRET_KEY.as_bytes())).unwrap()
}

pub fn offset_two_hours(offset_datetime: OffsetDateTime) -> OffsetDateTime {
   let two_hours = offset_datetime.to_offset(offset!(+2)).date();
   OffsetDateTime::now_utc().replace_date(two_hours)
}

fn create_and_add_cookie<'a>(token: &'a str, user_claims: &'a UserClaims) {
    let token_cookie = Cookie::build(("auth_token", token.to_owned()))
        .domain("http://127.0.0.1:8000/")
        .path("/dashboard/*")
        .http_only(true)
        .secure(true)
        .expires(offset_two_hours(OffsetDateTime::now_utc()));

    let user_claims_str = serde_json::to_string(&user_claims).unwrap();

    let user_cookie = Cookie::build(("user_claims", user_claims_str))
        .domain("http://127.0.0.1:8000/")
        .path("/dashboard/*")
        .http_only(true)
        .secure(true)
        .expires(offset_two_hours(OffsetDateTime::now_utc()));

    let mut jar = CookieJar::new();
    let mut private_jar = jar.private_mut(&get_cookie_key());
    private_jar.add(token_cookie);
    private_jar.add(user_cookie);

    let mut cookie_lock: std::sync::RwLockWriteGuard<'_, Option<CookieJar>> = COOKIE_JAR.write().unwrap();
    *cookie_lock = Some(jar);
}
