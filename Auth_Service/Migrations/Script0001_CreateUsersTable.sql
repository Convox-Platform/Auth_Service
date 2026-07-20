CREATE TABLE Users
(
    Id           BIGINT          NOT NULL PRIMARY KEY,
    Email        VARCHAR(256)    NOT NULL,
    PasswordHash TEXT            NULL,
    Delete_At    TIMESTAMP       NULL,  
    CONSTRAINT UQ_Users_Email UNIQUE (Email)


);
CREATE INDEX IX_Users_Delete_At
ON Users (Delete_At)
WHERE Delete_At IS NOT NULL;