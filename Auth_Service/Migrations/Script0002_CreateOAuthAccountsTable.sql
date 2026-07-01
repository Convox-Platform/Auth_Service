CREATE TABLE OAuth_accounts
(
    Id            NVARCHAR(255)  NOT NULL PRIMARY KEY,
    Provider      NVARCHAR(50)   NULL,
    Access_token  NVARCHAR(MAX)  NULL,
    Refresh_token NVARCHAR(MAX)  NULL,
    Expires_at    DATETIME2      NULL,
    Scope         NVARCHAR(MAX)  NULL,
    User_id       BIGINT         NULL,
    CONSTRAINT FK_OAuthAccounts_Users FOREIGN KEY (User_id) REFERENCES Users (Id)
);
