CREATE TABLE OAuth_accounts
(
    Id            VARCHAR(255)   NOT NULL PRIMARY KEY,
    Provider      VARCHAR(50)    NULL,
    Access_token  TEXT           NULL,
    Refresh_token TEXT           NULL,
    Expires_at    TIMESTAMP      NULL,
    Scope         TEXT           NULL,
    User_id       BIGINT         NULL,
    CONSTRAINT FK_OAuthAccounts_Users FOREIGN KEY (User_id) REFERENCES Users (Id) ON DELETE CASCADE
);