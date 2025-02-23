-- Create the database (if it doesn't exist)
CREATE DATABASE IF NOT EXISTS quorum_secrets;

-- Use the created database
USE quorum_secrets;

-- Create the 'Users' table
CREATE TABLE IF NOT EXISTS Users (
    Id BIGINT AUTO_INCREMENT PRIMARY KEY,              -- User Id, auto-incremented
    PublicKey TEXT NOT NULL,                           -- RSA 4096 Public Key
    Username VARCHAR(256) NOT NULL,                    -- Username, up to 256 chars
    Salt VARCHAR(32) NOT NULL,                              -- Salt, as long integer
    PasswordHash CHAR(64) NOT NULL,                    -- SHA-256 hash (64 chars hex)
    UNIQUE (Username),    
    INDEX idx_username (Username)                              -- Ensure the username is unique
);


-- Create the 'Secrets' table
CREATE TABLE IF NOT EXISTS Secrets (
    Id BIGINT AUTO_INCREMENT PRIMARY KEY,              -- Secret Id, auto-incremented
    Quorum SMALLINT NOT NULL,                          -- Quorum, short integer
    Cipher BLOB NOT NULL,                             -- Cipher, stored as BLOB
    Name VARCHAR(256) NOT NULL,                        -- Name of the secret, up to 256 chars
    Comments TEXT NOT NULL,                            -- Comments, up to 4096 chars
    StartingDate DATETIME DEFAULT NULL,                  -- Starting date, optional
    UNIQUE (Name),                                     -- Ensure the name is unique
    INDEX idx_name (Name)
);


-- Create the junction table for the many-to-many relationship
CREATE TABLE IF NOT EXISTS UserSecret (
    UserId BIGINT NOT NULL,                           -- Foreign key to User
    SecretId BIGINT NOT NULL,                         -- Foreign key to Secret
    IsOwner BOOLEAN NOT NULL,                         -- Boolean indicating if the user is the owner
    SecretShare VARCHAR(1024),                        -- Optional string for secret sharing details
    DecryptRequest BOOLEAN NOT NULL,                  -- Boolean indicating if decrypting is requested
    PRIMARY KEY (UserId, SecretId),                 -- Composite primary key on UserId and SecretId
    CONSTRAINT fk_user_id FOREIGN KEY (UserId)      -- Foreign key to User table
      REFERENCES Users (Id)
      ON DELETE CASCADE,                                -- Cascade delete if User is deleted
    CONSTRAINT fk_secret_id FOREIGN KEY (SecretId)  -- Foreign key to Secret table
      REFERENCES Secrets (Id)
      ON DELETE CASCADE                                 -- Cascade delete if Secret is deleted
) 
