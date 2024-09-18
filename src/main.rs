/* Our extern crates */
#[macro_use] extern crate diesel;
#[macro_use] extern crate rocket;

extern crate dotenv;

/* Importing functions */
use diesel::{
    connection::Connection,
    pg::PgConnection,
};

use dotenv::dotenv;
use std::env;
use std::path::{ Path, PathBuf };

// Rocket
use rocket::{
    fs::NamedFile,
    Request, 
    response::{ Flash, Redirect },
};

use rocket_dyn_templates::Template;

use crate::roosties::AuthenticatedUser;

use crate::users::UserClaims;

/* Declaring a module, just for separating things better */
pub mod roosties;
pub mod users;
pub mod bucket;
pub mod models;

/* auto-generated table macros */
pub mod schema;

/* This will return our pg connection to use with diesel */
pub fn establish_connection() -> PgConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");

    PgConnection::establish(&database_url)
        .expect(&format!("Error connecting to {}", database_url))
}

/*
pub fn parse_roosty(header: &ConnectionResult<T>) -> Result<Vec<T>, ConnectionError> {
    match header.get(0) {
        None => Err(E),
        Some(Vec) => Ok(),
        Some(_) => Err("Invalid Roosty"),
    }
}
*/

/* Static files Handler, will give back our heroes images */
#[get("/static/imgs/<file..>")]
async fn assets(file: PathBuf) -> Option<NamedFile> {
    NamedFile::open(Path::new("static/imgs/").join(file)).await.ok()
}

#[catch(404)]
fn not_found(req: &Request) -> Flash<Redirect> {
    println!("{:?}", req.cookies());
    Flash::error(
        Redirect::to("/"),
        "Invalid request"
    )
}

fn get_default_claims() -> UserClaims {
    UserClaims {
        username: "example_user".to_string(),
        sub: "0".to_string(),
        exp: chrono::Utc::now().timestamp() as i64,
    }
}
 
#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![
            assets,
            users::index,
            users::new_user,
            users::process_user,
            users::login,
            users::process_login
        ])
        .mount("/dashboard", routes![
            roosties::assets,
            roosties::private_user_profile,
            roosties::protected_roosty_upload,
            roosties::protected_roosty_insert,
            roosties::protected_roosty_update,
            roosties::protected_roosty_process_update,
            roosties::protected_roosty_delete,
            roosties::logout,
        ])
        .register("/", catchers![not_found])
        .attach(Template::fairing())
        .manage(AuthenticatedUser { claims: get_default_claims() })
}