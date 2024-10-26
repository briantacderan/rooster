// To be able to return Templates 
use std::{
    collections::HashSet,
    default::Default,
    path::{ Path, PathBuf }
};

// Diesel query builder 
use diesel::prelude::*;

// Rocket
use rocket::fs::NamedFile;

/* To be able to parse raw forms */
use rocket::{
    data::Data, get, 
    http::{ ContentType, Status },
    response::{ 
        Flash, Redirect
    },
    request::{ 
        FromRequest, Request, FlashMessage, Outcome
    },
    tokio,
};

use cookie::{ CookieJar, PrivateJar };

use rocket_dyn_templates::Template;

use rocket_multipart_form_data::{
    MultipartFormData, 
    MultipartFormDataField, 
    MultipartFormDataOptions,   
};

use chrono::{
    Local,
    DateTime,
    NaiveDateTime,
};

use crate::{
    bucket::{
        remove_object, upload_object, get_object_uri
    }, establish_connection, models::{ NewRoosty, Roosty }, schema::*, users::{ 
        get_cookie_jar, get_cookie_key, get_secret_key, UserClaims, COOKIE_JAR
    }
};

use serde::{ Serialize, Deserialize };

use jsonwebtoken::{ 
    Validation, decode, DecodingKey
};





/* List our inserted heroes */
#[get("/<username>")]
pub async fn private_user_profile(
    flash: Option<FlashMessage<'_>>, 
    user: AuthenticatedUser<UserClaims>,
    username: &str
) -> Template {
    if user.claims.username != username {
        println!("Authorized for user: {}", user.claims.username);
        println!("Requested page of: {}", username);

        let authorized_username = &user.claims.username.clone();
        
        Template::render("unauthorized", &TemplateContext {
            roosties: None,
            flash: "You are not authorized to view this page",
            user: user,
            username: &authorized_username,
            id: None
        })
    } else {
        let user_claims: &UserClaims = &user.claims;
        let mut conn = establish_connection();
        
        let user_id: i32 = user_claims.sub.parse().expect("Invalid user ID");

        /* Get all our roosties from database */
        let roosties: Vec<Roosty> = roosties::table
            .select(roosties::all_columns)
            .filter(roosties::user_id.eq(&user_id))
            .load::<Roosty>(&mut conn)
            .expect("Whoops, like this went bananas!");

        let mut message: &str = "";
    
        if let Some(ref flash) = flash {
            message = flash.message();
        }

        let dashboard = TemplateContext {
            roosties: Some(roosties),
            flash: message,
            user: user,
            username: username,
            id: None
        };

        /* Return the template */
        Template::render("dashboard", &dashboard)
    }
}

#[get("/<username>/roosty/upload/new", rank = 1)]
pub fn protected_roosty_upload(
    flash: Option<FlashMessage>,
    user: AuthenticatedUser<UserClaims>,
    username: &str
) -> Template {
    let flash_message: &str;
    if let Some(ref msg) = flash {
        flash_message = msg.message();
    } else {
        flash_message = "";
    }

    let dashboard = TemplateContext {
        roosties: None,
        flash: flash_message,
        user: user,
        username: username,
        id: None
    };

    Template::render("upload", &dashboard)
}

#[post("/<username>/roosty/upload/processing", data = "<roosty_data>")]
pub async fn protected_roosty_insert(
    content_type: &ContentType, 
    user: AuthenticatedUser<UserClaims>, 
    username: &str,
    roosty_data: Data<'_>
) -> Flash<Redirect> {
    let mut conn = establish_connection();

    /* First we declare what we will be accepting on this form */
    let mut options = MultipartFormDataOptions::new();

    options.allowed_fields = vec![
        MultipartFormDataField::file("spotted_photo"),
        MultipartFormDataField::text("fantasy_name"),
        MultipartFormDataField::text("real_name"),
        MultipartFormDataField::text("strength_level"),
    ];

    /* If stuff matches, do stuff */
    let multipart_form_data = MultipartFormData::parse(content_type, roosty_data, options).await;

    match multipart_form_data {
        Ok(form) => {
            /* If everything is ok, we will move the image and the insert into our datatabase */
            let roosty_img = match form.files.get("spotted_photo") {
                Some(img) => {

                    // AWS file system

                    let file_field = &img[0];
                    let bucket_name: &str = "rooster-buck";

                    let _dir_path = format!("imgs/{}", username.to_lowercase());
                    let _user_folder = Path::new(&_dir_path);
                    let file_name = &file_field.file_name;

                    let file_path = &file_field.path.clone();
                    let key = _user_folder.join(file_name.clone().unwrap().to_owned()).to_str().unwrap().to_owned();

                    let s3_object = upload_object(bucket_name, &key, file_path).await;
                    
                    match s3_object {
                        Ok(output) => {
                            println!("Uploaded object to S3 with eTag: {:?}", output.e_tag());
                            // let absolute_path = format!("https://{}.s3.us-west-1.amazonaws.com/{}", bucket_name, &key);
                            let expiration = 604799;
                            let presigned_url = get_object_uri(bucket_name, &key, expiration).await;
                            Ok(presigned_url.unwrap().clone())
                        },
                        Err(_) => Err("Failed to upload object to S3")
                    }
                   
                    // Application ROOT file system

                    /* let file_field = &img[0];
                    let _content_type = &file_field.content_type;
                    let _file_name = &file_field.file_name;
                    let _path = &file_field.path;           

                    // Lets split name to get format 
                    // Reparsing the fileformat
                    // let _format: Vec<&str> = _file_name.as_ref().unwrap().split('.').collect(); 
                    let _dir_path = format!("static/imgs/{}", username);
                    let user_folder = Path::new(&_dir_path);

                    // Create the user folder if it doesn't exist
                    if !user_folder.exists() {
                        match tokio::fs::create_dir_all(user_folder).await {
                            Ok(_) => println!("Created folder: {}", user_folder.display()),
                            Err(err) => println!("Error creating folder: {}", err),
                        }
                    }

                    let absolute_path: String = format!("{}/{}", _dir_path, _file_name.clone().unwrap());
                    // let absolute_path = PathBuf::from(absolute_path);
                    // instead...
                    tokio::fs::copy(_path, &absolute_path).await.unwrap(); 

                    if let Err(err) = tokio::fs::copy(_path, &absolute_path).await {
                        return Flash::error(
                            Redirect::to(format!("/dashboard/{}/roosty/upload/new", username)),
                            format!(
                                "Houston, We have problems parsing our form... Debug info: {}",
                                err
                            ),
                        );
                    }

                    Some(absolute_path) */
                },
                None => Err("No image found")
            };

            let dt: DateTime<Local> = Local::now();
            let naive_utc: NaiveDateTime = dt.naive_utc();

            /* Insert our form data inside our database */
            let insert = diesel::insert_into(roosties::table)
                .values(NewRoosty {
                    user_id: user.claims.sub.parse().unwrap(), 
                    fantasy_name: match form.texts.get("fantasy_name") {
                        Some(value) => &value[0].text,
                        None => "No Name",
                    },
                    real_name: match form.texts.get("real_name") {
                        Some(content) => Some(&content[0].text),
                        None => None,
                    },
                    spotted_photo: &roosty_img.unwrap().to_owned(),
                    file_name: match form.files.get("spotted_photo") {
                        Some(img) => &img[0].file_name.as_ref().unwrap(),
                        None => "No Name",
                    },
                    strength_level: match form.texts.get("strength_level") {
                        Some(level) => level[0].text.parse::<i32>().unwrap(),
                        None => 0,
                    },
                    created_at: naive_utc,
                    updated_at: naive_utc,
                    deleted_at: None,
                })
                .execute(&mut conn);

            match insert {
                Ok(_) => Flash::success(
                    Redirect::to(format!("/dashboard/{}", username)),
                    "Success! We got your new Roosty on the database!",
                ),
                Err(err_msg) => Flash::error(
                    Redirect::to(format!("/dashboard/{}/roosty/upload/new", username)),
                    format!(
                        "Houston, We had problems while inserting things into our database ... {}",
                        err_msg
                    ),
                ),
            }
        }
        Err(err_msg) => {
            /* Falls to this pattern if theres some fields that isn't allowed or bolsonaro rules this code */
            Flash::error(
                Redirect::to(format!("/dashboard/{}/roosty/upload/new", username)),
                format!(
                    "Houston, We have problems parsing our form... Debug info: {}",
                    err_msg
                ),
            )
        }
    }
}

#[get("/<username>/roosty/<id>/update", rank = 1)]
pub fn protected_roosty_update(
    flash: Option<FlashMessage>, 
    user: AuthenticatedUser<UserClaims>,
    username: &str,
    id: i32
) -> Template { 
    let user_id: i32 = user.claims.sub.parse::<i32>().unwrap();
    let mut conn = establish_connection();

    let data = roosties::table
        .select(roosties::all_columns)
        .filter(roosties::user_id.eq(user_id))
        .filter(roosties::id.eq(id))
        .load::<Roosty>(&mut conn)
        .expect("Something happened while retrieving the roosty based on this ID");

    let flash_message: &str;

    if let Some(ref flash) = flash {
        flash_message = flash.message();
    } else {
        flash_message = "";
    }

    let dashboard = TemplateContext {
        roosties: Some(data),
        user: user,
        flash: flash_message,
        username: username,
        id: Some(id)
    };

    Template::render("update", &dashboard)
}

#[post("/<username>/roosty/<id>/update/processing", data = "<roosty_data>")]
pub async fn protected_roosty_process_update(
    content_type: &ContentType, 
    user: AuthenticatedUser<UserClaims>, 
    username: &str,
    id: i32,
    roosty_data: Data<'_>
) -> Flash<Redirect> {
    let user_id: i32 = user.claims.sub.parse::<i32>().unwrap();
    let mut conn = establish_connection();

    /* First we declare what we will be accepting on this form */
    let mut options = MultipartFormDataOptions::new();

    options.allowed_fields = vec![
        MultipartFormDataField::file("spotted_photo"),
        MultipartFormDataField::text("fantasy_name"),
        MultipartFormDataField::text("real_name"),
        MultipartFormDataField::text("strength_level"),
    ];

    /* If stuff matches, do stuff */
    let multipart_form_data = MultipartFormData::parse(content_type, roosty_data, options).await;

    match multipart_form_data {
        Ok(form) => {
            /* If everything is ok, we will move the image and the insert into our datatabase */
            let roosty_img = match form.files.get("spotted_photo") {
                Some(img) => {

                    // AWS file system

                    let file_field = &img[0];
                    let bucket_name: &str = "rooster-buck";

                    let _dir_path = format!("imgs/{}", username.to_lowercase());
                    let _user_folder = Path::new(&_dir_path);
                    let file_name = &file_field.file_name;

                    let file_path = &file_field.path.clone();
                    let key = _user_folder.join(file_name.clone().unwrap().to_owned()).to_str().unwrap().to_owned();

                    let s3_object = upload_object(bucket_name, &key, file_path).await;
                    
                    match s3_object {
                        Ok(_output) => {
                            println!("Uploaded the updated object to S3 with eTag: {:?}", _output.e_tag());
                            let expiration = 604799;
                            let presigned_url = get_object_uri(bucket_name, &key, expiration).await;
                            Ok(presigned_url.unwrap().clone())
                        },
                        Err(_) => Err("Failed to upload updated object to S3")
                    }

                    // Application ROOT file system

                    /*let file_field = &img[0];
                    let _content_type = &file_field.content_type;
                    let _file_name = &file_field.file_name;
                    let _path = &file_field.path;

                    /* Path parsing */
                    let _dir_path = format!("static/imgs/{}", username);

                    let absolute_path: String = format!("{}/{}", _dir_path, _file_name.clone().unwrap());
                    tokio::fs::copy(_path, &absolute_path).await.unwrap();

                    if let Err(err) = tokio::fs::copy(_path, &absolute_path).await {
                        return Flash::error(
                            Redirect::to(format!("/dashboard/{}/roosty/{}/update", username, id)),
                            format!(
                                "Houston, We have problems parsing our form... Debug info: {}",
                                err
                            ),
                        );
                    }

                    Some(absolute_path) */
                }
                None => Err("No image found")
            };

            let roosty_table = roosties::table
                .select(roosties::all_columns)
                .filter(roosties::id.eq(&id))
                .load::<Roosty>(&mut conn)
                .expect("Whoops, like this went bananas!");

            let dt: DateTime<Local> = Local::now();
            let naive_utc: NaiveDateTime = dt.naive_utc();

            /* Insert our form data inside our database */
            let insert = diesel::update(roosties::table)
                .filter(roosties::user_id.eq(&user.claims.sub.parse::<i32>().unwrap()))
                .filter(roosties::id.eq(&id))
                .set(NewRoosty {
                    user_id: user_id, 
                    fantasy_name: match form.texts.get("fantasy_name") {
                        Some(value) => &value[0].text,
                        None => "No Name.",
                    },
                    real_name: match form.texts.get("real_name") {
                        Some(content) => Some(&content[0].text),
                        None => None,
                    },
                    spotted_photo: &roosty_img.unwrap().to_owned(),
                    file_name: match form.files.get("spotted_photo") {
                        Some(img) => &img[0].file_name.as_ref().unwrap(),
                        None => "No Name",
                    },
                    strength_level: match form.texts.get("strength_level") {
                        Some(level) => level[0].text.parse::<i32>().unwrap(),
                        None => 0,
                    },
                    created_at: roosty_table.first().unwrap().created_at,
                    updated_at: naive_utc,
                    deleted_at: None,
                })
                .execute(&mut conn);

            match insert {
                Ok(_) => Flash::success(
                    Redirect::to(format!("/dashboard/{}", username)),
                    "Success! We got your updated roosty on our database!",
                ),
                Err(err_msg) => Flash::error(
                    Redirect::to(format!("/dashboard/{}/roosty/{}/update", username, id)),
                    format!(
                        "Houston, We had problems while updating your roosty into our database ... {}",
                        err_msg
                    ),
                ),
            }
        }
        Err(err_msg) => Flash::error(
            Redirect::to(format!("/dashboard/{}/roosty/{}/update", username, id)),
            format!(
                "Houston, We have problems parsing our form... Debug info: {}",
                err_msg
            ),
        )
    }
}

#[post("/<username>/roosty/<id>/delete")]  //, rank = 1)]
pub async fn protected_roosty_delete(
    user: AuthenticatedUser<UserClaims>,
    username: &str,
    id: i32
) -> Flash<Redirect> {
    let mut conn = establish_connection();

    let roosty_table = roosties::table
        .select(roosties::all_columns)
        .filter(roosties::id.eq(&id))
        .load::<Roosty>(&mut conn)
        .expect("Whoops, like this went bananas!");

    let bucket_name: &str = "rooster-buck";
    let _dir_path = format!("imgs/{}", username.to_lowercase());
    let _user_folder = Path::new(&_dir_path);
    let _file_name = &roosty_table.first().unwrap().file_name;
    let key = _user_folder.join(_file_name).to_str().unwrap().to_owned();
    
    println!("Deleting KEY: {}", &key);

    match remove_object(bucket_name, &key).await {
        Ok(()) => {
            println!("Removed the object from S3");

            /* Delete the roosty from our database */

            diesel::delete(roosties::table
                .filter(roosties::user_id.eq(&user.claims.sub.parse::<i32>().unwrap()))
                .filter(roosties::id.eq(&id))
            )
            .execute(&mut conn)
            .expect("Error deleting the roosty");

            Flash::success(
                Redirect::to(format!("/dashboard/{}", username)),
                "Success! We got rid of your roosty on our database!",
            )
        },
        Err(err_msg) => Flash::error(
            Redirect::to(format!("/dashboard/{}", username)),
            format!(
                "Houston, We have problems removing the object from S3: {}",
                err_msg
            ),
        ),
    }
}

#[get("/logout")]
pub fn logout(user: AuthenticatedUser<UserClaims>) -> Flash<Redirect> {
    remove_cookies();

    Flash::success(
        Redirect::to("/login"),
        format!("You are now logged out. Goodbye, {}!", &user.claims.username)
    )
}






#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatedUser<UserClaims> {
    pub claims: UserClaims,
}

impl<UserClaims: Default> Default for AuthenticatedUser<UserClaims> {
    fn default() -> Self {
        AuthenticatedUser {
            claims: Default::default(),
        }
    }
}

#[derive(Debug)]
pub struct AuthenticatedUserError;

pub async fn verify_token(token: &str) -> bool {
    let mut validation = Validation::default();
    let mut required_claims = HashSet::with_capacity(1);
    required_claims.insert("exp".to_owned());
    validation.required_spec_claims = required_claims;

    decode::<UserClaims>(
        token,
        &DecodingKey::from_secret(&get_secret_key().as_bytes()),
        &validation,
    )
    .is_ok()
}

pub fn get_cookie_values(jar: CookieJar) -> Result<(String, String), ()> {
    let key = get_cookie_key();
    let private_jar: PrivateJar<&CookieJar> = jar.private(&key);

    println!("CookieJar contents: {:?}", jar);

    let auth_token_cookie = private_jar.get("auth_token");
    let user_claims_cookie = private_jar.get("user_claims");
 
    println!("Getting cookies...");

    println!("Authorization Cookie: {:?}", &auth_token_cookie);
    println!("Claims Cookie: {:?}", &user_claims_cookie);

    if let (Some(auth_token), Some(user_claims)) = (auth_token_cookie, user_claims_cookie) {
        let auth_token_value = auth_token.value().to_string();
        let user_claims_value = user_claims.value().to_string();
        println!("Authorization Token: {}", &auth_token_value);
        println!("User Claims: {}", &user_claims_value);
        Ok((auth_token_value, user_claims_value))
    } else {
        Err(())
    }
}

// GET or INITIALIZE JAR
pub fn remove_cookies() {
    let mut cookie_jar = COOKIE_JAR.write().unwrap();
    *cookie_jar = Some(CookieJar::new());
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser<UserClaims> {
    type Error = AuthenticatedUserError;

    async fn from_request(_req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let jar: CookieJar = get_cookie_jar().unwrap().clone();  // req.cookies();

        if let Ok((auth_token_string, user_claims_string)) = get_cookie_values(jar).to_owned() {
            let clms: UserClaims = serde_json::from_str(&user_claims_string).unwrap();
            if verify_token(&auth_token_string).await {
                let user = AuthenticatedUser {
                    claims: UserClaims {
                        username: clms.username,
                        sub: clms.sub,
                        exp: clms.exp,
                    }
                };
                
                Outcome::Success(user)
            } else {
                Outcome::Error((Status::Unauthorized, AuthenticatedUserError))
            }
        } else {
            Outcome::Error((Status::BadRequest, AuthenticatedUserError))
        }
    }
}

#[derive(Serialize)]
struct TemplateContext<'a> {
    roosties: Option<Vec<Roosty>>,
    flash: &'a str,
    user: AuthenticatedUser<UserClaims>,
    username: &'a str,
    id: Option<i32>
}

// Static files Handler, will give back our heroes images 
#[get("/imgs/<username>/<file..>", rank = 2)]
pub async fn assets(
    file: PathBuf,
    username: &str
) -> Option<NamedFile> {
    let path_string = format!("static/imgs/{}/", username.to_lowercase());
    let user_folder = Path::new(&path_string);

    // Create the user folder if it doesn't exist
    if !user_folder.exists() {
        match tokio::fs::create_dir_all(user_folder).await {
            Ok(_) => println!("Created folder: {}", user_folder.display()),
            Err(err) => println!("Error creating folder: {}", err),
        }
    }

    let file_path = user_folder.join(file);
    let file = NamedFile::open(file_path).await.ok();
    file
} 