CREATE TABLE Users
(
    Id           BIGINT          NOT NULL PRIMARY KEY,
    Email        VARCHAR(256)    NOT NULL,
    PasswordHash TEXT            NULL,
    CONSTRAINT UQ_Users_Email UNIQUE (Email)
);