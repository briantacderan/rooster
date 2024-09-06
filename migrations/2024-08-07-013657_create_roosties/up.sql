CREATE TABLE roosties (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    fantasy_name VARCHAR NOT NULL,
    real_name VARCHAR NULL,
    spotted_photo TEXT NOT NULL,
    strength_level INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)  
);