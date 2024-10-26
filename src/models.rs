/* Import macros and others */
use crate::schema::*;

use chrono::{
    self, NaiveDateTime
};

/* For being able to serialize */
use serde::Serialize;

// use pbkdf2::password_hash::PasswordHash;


/* #[derive(debug)]
pub struct NewUserHash<'a, 'b> where NewPasswordHash<'a>: PasswordHash<'a> {
    pub rounds: u32,
    pub hash: &'a [u8],
    pub salt: &'a mut [u8],
    pub algo: pbkdf2::Algorithm,
}

pub impl<'a> PasswordHash<'a> for PasswordHash<'b> {
    fn new(password: &'a str, salt: &'a mut [u8]) -> PasswordHash<'a> {
        let algo = pbkdf2::Algorithm::default();
        let rounds = 100_000;
        let hash = HASHER;
        PasswordHash { hash, salt, algo, rounds, hash }
        // PasswordHash { hash: HASHER, salt, algo, rounds, hash }
    }
} 

/* Static variables */
pub static HASHER: [u8; 32] = [0; 32]; */

/* Models */
#[derive(Debug, Queryable, Serialize, Identifiable)]
#[diesel(table_name = users)]
pub struct User {
    pub id: i32,
    pub email: String,
    pub username: String,
    pub password: String,
    pub tier: i32,
    pub admin: bool,
    pub full_name: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub deleted_at: Option<NaiveDateTime>,
}

#[derive(Debug, Serialize, Insertable, AsChangeset)]
#[diesel(table_name = users)]
pub struct NewUser<'x> {
    pub email: &'x str,
    pub username: &'x str,
    pub password: &'x str,
    pub tier: i32,
    pub admin: bool,
    pub full_name: Option<&'x str>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub deleted_at: Option<NaiveDateTime>,
}

#[derive(Debug, Queryable, Serialize, Identifiable)]
#[diesel(table_name = roosties)]
pub struct Roosty {
    pub id: i32, 
    pub user_id: i32,
    pub fantasy_name: String,
    pub real_name: Option<String>,
    pub spotted_photo: String,
    pub file_name: String,
    pub strength_level: i32,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub deleted_at: Option<NaiveDateTime>,
}

#[derive(Debug, Serialize, Insertable, AsChangeset)]   // Insertable, AsChangeset
#[diesel(table_name = roosties)]
pub struct NewRoosty<'x> {
    pub user_id: i32,
    pub fantasy_name: &'x str,
    pub real_name: Option<&'x str>,
    pub spotted_photo: &'x str,
    pub file_name: &'x str,
    pub strength_level: i32,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub deleted_at: Option<NaiveDateTime>,
}

/* #[derive(Debug)]
pub enum RoostyEnum {
    Int(i32),
    String,
}

pub fn roosty_enumerator() -> &Vec<Roosty> {
    let id = RoostyEnum::Int(i32);
    let fan = RoostyEnum::String;
    let rn = RoostyEnum::Option<String>;
    let sp = RoostyEnum::String;
    let sl = RoostyEnum::Int(i32);

    let mut roostyvec = vec![id, fan, rn, sp, sl];

    for roosty in &roostyvec {

    }
} */
