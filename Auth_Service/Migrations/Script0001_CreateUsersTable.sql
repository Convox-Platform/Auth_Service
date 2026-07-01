CREATE TABLE Users
(
    Id           BIGINT          NOT NULL PRIMARY KEY,
    Email        NVARCHAR(256)   NOT NULL,
    PasswordHash NVARCHAR(MAX)   NULL,
    CONSTRAINT UQ_Users_Email UNIQUE (Email)
);
