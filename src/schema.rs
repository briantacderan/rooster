// @generated automatically by Diesel CLI.

diesel::table! {
    roosties (id) {
        id -> Int4,
        user_id -> Int4,
        fantasy_name -> Varchar,
        real_name -> Nullable<Varchar>,
        spotted_photo -> Text,
        strength_level -> Int4,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        deleted_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    users (id) {
        id -> Int4,
        email -> Varchar,
        username -> Text,
        password -> Text,
        tier -> Int4,
        admin -> Bool,
        full_name -> Nullable<Varchar>,
        created_at -> Timestamp,
        updated_at -> Timestamp,
        deleted_at -> Nullable<Timestamp>,
    }
}

diesel::joinable!(roosties -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    roosties,
    users,
);
