CREATE TABLE JWT_tokens
(
    Id           INT IDENTITY (1,1) NOT NULL PRIMARY KEY,
    RefreshToken NVARCHAR(MAX)      NOT NULL,
    Expires_at   DATETIME2          NOT NULL,
    User_id      BIGINT             NULL,
    CONSTRAINT FK_JwtTokens_Users FOREIGN KEY (User_id) REFERENCES Users (Id)
);
