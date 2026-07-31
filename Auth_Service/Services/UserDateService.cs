using Auth_Service.Models;
using Dapper;
using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using Grpc.Net.Client;
using Grpc.Net.Client.Web;
using Mail.V1;
using Microsoft.AspNetCore.Authorization;
using System.Data.Common;
using System.Security.Claims;
using User_Service;
using UserDate_Service;

namespace Auth_Service.Services
{
    public class UserDateService: UserDate.UserDateBase
    {

        // количиество дней до удаления
        private readonly int DeleteDate = 14;

        private readonly DbConnection _db;
        private ConfirmationStore _confirmationStore;
        private readonly string _mailServiceUrl;
        private readonly string _userServiceUrl;

        private readonly string[] _origins;
        private readonly string _secretKey;

        [Authorize]
        public override async Task<UserDateResponse> GetUserId(Empty request, ServerCallContext context)
        {
            var httpContext = context.GetHttpContext();
            var userId = Convert.ToInt64( httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier));
            return new UserDateResponse { UserId = userId };
        }
        public override async Task<UserDateBoolResponse> IsUserExist(UserDateResponse request, ServerCallContext context)
        {
            string sql = """
            SELECT EXISTS (
            SELECT 1
            FROM users
            WHERE id = @Id
            );
            """;
            bool exist = await _db.ExecuteScalarAsync<bool>(sql, new { Id = request.UserId });

            return new UserDateBoolResponse { IsExist = exist };
        }

        [Authorize]
        public override async Task<UserDateDeleteResponse> DeleteUser(UserDateResponse request, ServerCallContext context)
        {
            var grpcWebHandler = new GrpcWebHandler(GrpcWebMode.GrpcWeb, new SocketsHttpHandler());
            using var channel = GrpcChannel.ForAddress(_mailServiceUrl, new GrpcChannelOptions { HttpHandler = grpcWebHandler });

            var userid = Convert.ToInt64(context.GetHttpContext().User.FindFirstValue(ClaimTypes.NameIdentifier));

            Console.WriteLine($"context userId: {userid} request userId: {request.UserId}");

            if (userid == request.UserId)
            {
                var client = new MailService.MailServiceClient(channel);
                var sql = """
                    UPDATE users 
                    SET delete_at = now() + interval '@Days day'
                    WHERE id = @Id;
                    """;// 1 день только на время, а вообще должно быть 14 дней

                await _db.ExecuteAsync(sql, new { Id = request.UserId });

                var sqlUser = """
                    SELECT email FROM users WHERE id = @Id;
                    """;
                var email = await _db.QueryFirstOrDefaultAsync<string>(sqlUser, new { Id = request.UserId, Days = DeleteDate });

                await client.SendEmailAsync(new SendEmailRequest { RecipientEmail = email, Body = await MakeMailBodyForDelete() });

                return new UserDateDeleteResponse { Result = true };
            }



            return new UserDateDeleteResponse{ Result = false };

            
        }

        [Authorize]
        public override async Task<UserDateBoolResponse> CheckPassword(PasswordReqest request, ServerCallContext context)
        {
            var userId =Convert.ToInt64( context.GetHttpContext().User.FindFirstValue(ClaimTypes.NameIdentifier));
            if (userId > 0)
            {
                if (request.UserId != userId)
                    throw new RpcException(new Status(StatusCode.PermissionDenied, "You can't change password for other account"));
            }
            
            
            var sql = "SELECT * FROM users WHERE id = @id";

            if (request.Password == null) 
                throw new RpcException(new Status(StatusCode.InvalidArgument, "Password is null"));

            var user = await _db.QueryFirstOrDefaultAsync<User>(sql, new { id = request.UserId });

            if (BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash)) 
                return new UserDateBoolResponse { IsExist = true };

            return new UserDateBoolResponse { IsExist = false };
        }

        public override async Task<OperIdResponce> ChangeForgotPassword(ChangeForgotPasswordReqest request, ServerCallContext context)
        {
            
            string code = Random.Shared.Next(1_000, 999_999).ToString("D6");

            var Handler = new GrpcWebHandler(GrpcWebMode.GrpcWeb, new SocketsHttpHandler());
            var channel = GrpcChannel.ForAddress(_mailServiceUrl, new GrpcChannelOptions { HttpHandler = Handler });

            var client = new MailService.MailServiceClient(channel);

            var sql = "SELECT * FROM users WHERE email = @email";
            var user = await _db.QueryFirstOrDefaultAsync<User>(sql, new { email = request.Email });

            // запись в кэш
            var operationId = await _confirmationStore.CreateWithEmail(request.Email, code);

            await client.SendEmailAsync(new SendEmailRequest { RecipientEmail = request.Email, Body = await MakeMailBodyForChangePasswort(request.Email, user.Id, code) });

            
            return new OperIdResponce { OperId = operationId };
        }

        public override async Task<UserDateBoolResponse> CheckChangePasswordCode(PasswordCodeReqest request, ServerCallContext context)
        {
            var confirmation = await _confirmationStore.TryGet(request.OperId);


            if (confirmation == null)
                throw new RpcException(new Status(StatusCode.NotFound, "Confirmation not found"));

            if (confirmation.Code != request.Code)
                throw new RpcException(new Status(StatusCode.PermissionDenied, "Wrong code"));

            string sql = "SELECT * FROM users WHERE email = @email";
            var user = await _db.QueryFirstOrDefaultAsync<User>(sql, new { email = confirmation.Email });

            var PasswordCheck = await this.CheckPassword(new PasswordReqest { Password = request.Password, UserId = user.Id }, context);
            if (PasswordCheck.IsExist) // если пароль совпадает
                throw new RpcException(new Status(StatusCode.PermissionDenied, "Password is the same as before"));

            var newPassHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

            string sqlUpdate = "UPDATE users SET passwordhash = @hash WHERE Id = @id";
            await _db.ExecuteAsync(sqlUpdate, new { hash = newPassHash, Id = user.Id });


            return new UserDateBoolResponse { IsExist = true };

        }

        [Authorize]
        public override async Task<UserDateBoolResponse> ChangePassword(ChangePasswordReqest request, ServerCallContext context)
        {
            long UserId = Convert.ToInt64(context.GetHttpContext().User.FindFirstValue(ClaimTypes.NameIdentifier));
            if (request.UserId != UserId)
                throw new RpcException(new Status(StatusCode.PermissionDenied, "You can't change password for other account"));


            var PasswordCheck = await this.CheckPassword(new PasswordReqest { Password = request.Password, UserId = request.UserId }, context);

            if (!PasswordCheck.IsExist)
                throw new RpcException(new Status(StatusCode.PermissionDenied, "Wrong password"));

            var newPassHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword);

            string sqlUpdate = "UPDATE users SET passwordhash = @hash WHERE id = @id";
            await _db.ExecuteAsync(sqlUpdate, new { hash = newPassHash, id = request.UserId });

            return new  UserDateBoolResponse { IsExist = true };

           
        }

        

        [Authorize]
        public override async Task<UserDateBoolResponse> AddPasswordToAccount(PasswordReqest request, ServerCallContext context)
        {
            long UserId = Convert.ToInt64( context.GetHttpContext().User.FindFirstValue(ClaimTypes.NameIdentifier));
            if (request.UserId != UserId)
                throw new RpcException(new Status(StatusCode.PermissionDenied, "You can't change password for other account"));

            string sqlCheck = """
                                SELECT EXISTS (
                    SELECT 1
                    FROM OAuth_accounts
                    WHERE User_id = @UserId
                );
                """;
            bool isExist = await _db.ExecuteScalarAsync<bool>(sqlCheck, new { UserId = request.UserId });

            if (!isExist)
                throw new RpcException(new Status(StatusCode.PermissionDenied, "User has no OAuth accounts"));

            string sqlUpdate = "UPDATE users SET passwordhash = @hash WHERE id = @id";
            var hash = BCrypt.Net.BCrypt.HashPassword(request.Password);
            await _db.ExecuteAsync(sqlUpdate, new { hash = hash, id = request.UserId });

            return new UserDateBoolResponse { IsExist = true };


        }

        public UserDateService(DbConnection db, ConfirmationStore confirmationStore, [FromKeyedServices("mail_service_url")] string mailServiceUrl,
            [FromKeyedServices("secret_key")] string secretKey, [FromKeyedServices("origins")] string[] origins, [FromKeyedServices("user_service_url")] string userServiceUrl)
        {
            _db = db;
            _confirmationStore = confirmationStore;
            _mailServiceUrl = mailServiceUrl;
            _secretKey = secretKey;
            _origins = origins;
            _userServiceUrl = userServiceUrl;
        }



        private async Task<string> MakeMailBodyForDelete()
        {
            var imagesDirectory = Path.Combine(AppContext.BaseDirectory, "Images");
            var big_img = await File.ReadAllBytesAsync(
                Path.Combine(imagesDirectory, "logotype_big.png"));
            var footer_img = await File.ReadAllBytesAsync(
                Path.Combine(imagesDirectory, "logotype_footer.png"));  

            DateTime deleteDate = DateTime.UtcNow.AddDays(DeleteDate);
            string link = _origins[0] +"/app/login";

            string body = $"""
                                <!DOCTYPE html>
                <html lang="en">
                <head>
                  <meta charset="UTF-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1.0">
                  <title>Convox account deletion</title>
                </head>
                <body style="margin:0;padding:40px 20px;background:#fff;font-family:Arial,sans-serif;color:#111">

                <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                  <tr>
                    <td align="center">

                      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:680px">

                        <tr>
                          <td align="center" style="padding-bottom:30px">
                            <div style="font-size:32px;font-weight:800;letter-spacing:2px;color:#20293A">
                              <img src="data:image/png;base64,{Convert.ToBase64String(big_img)}" alt="Convox">
                            </div>
                          </td>
                        </tr>

                        <tr>
                          <td align="center">
                            <h1 style="margin:0 0 35px;font-size:38px;line-height:46px">
                              Your Convox account<br>will be Deleted
                            </h1>
                          </td>
                        </tr>

                        <tr>
                          <td style="font-size:20px;line-height:30px">
                            <p style="margin:0 0 25px">
                              Your account has been inactive and will be deleted within {DeleteDate} days.
                            </p>

                            <p style="margin:0">
                              To keep it active, log in by <strong>{deleteDate.ToString("MMMM dd ")+ ", " + deleteDate.ToString("yyyy")}</strong>.
                            </p>
                          </td>
                        </tr>

                        <tr>
                          <td align="center" style="padding:40px 0">
                            <a href="{link}"
                               target="_blank"
                               style="display:inline-block;width:300px;padding:18px 0;background:#4560ED;border-radius:10px;color:#fff;font-size:18px;font-weight:bold;text-decoration:none">
                              Login
                            </a>
                          </td>
                        </tr>

                        <tr>
                          <td style="padding-bottom:60px;font-size:18px;line-height:28px">
                            After deletion, contact Customer Service to restore access.
                          </td>
                        </tr>

                        <tr>
                          <td style="padding-bottom:20px;font-size:14px;line-height:21px;color:#888">
                            This automated email was sent because you have a Convox account.
                            Please do not reply.
                          </td>
                        </tr>

                        <tr>
                          <td style="border-top:1px solid #ccc;padding:20px 0 60px;font-size:15px">
                            Need help?
                            <a href="mailto:help@convox.social" style="color:#111">
                              help@convox.social
                            </a>
                          </td>
                        </tr>

                        <tr>
                          <td>
                            <div style="font-size:24px;font-weight:800;letter-spacing:2px;color:#20293A">
                                <img src="data:image/png;base64,{Convert.ToBase64String(footer_img)}" alt="Convox">
                            </div>
                          </td>
                        </tr>

                      </table>

                    </td>
                  </tr>
                </table>

                </body>
                </html>
                """;

            return body;
        }

        private async Task<string> MakeMailBodyForChangePasswort(string email,long id,string code)
        {
            var tokens = JWTAuthService.JWTTokenGenerator(email, id, _secretKey);

            var handler = new GrpcWebHandler(GrpcWebMode.GrpcWeb);
            var channel = GrpcChannel.ForAddress(_userServiceUrl, new GrpcChannelOptions { HttpHandler = handler });

            var client = new UserService.UserServiceClient(channel);

            var header = new Metadata
            {
                { "Authorization", "Bearer " + tokens.AccessToken }
            };

            var profile = await client.GetUserProfileAsync(new GetUserProfileRequest { UserId = id }, new CallOptions(header));
            string username = profile.Username;

            var imagesDirectory = Path.Combine(AppContext.BaseDirectory, "Images");
            var big_img = await File.ReadAllBytesAsync(
                Path.Combine(imagesDirectory, "logotype_big.png"));
            var footer_img = await File.ReadAllBytesAsync(
                Path.Combine(imagesDirectory, "logotype_footer.png"));

            var body = $"""
                <!DOCTYPE html>
                <html lang="en">
                <body style="margin:0;padding:40px 15px;font-family:Arial,sans-serif;color:#202020">
                
                <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                <td align="center">
                
                <table width="100%" cellpadding="0" cellspacing="0"
                       style="max-width:600px">
                
                    <tr>
                        <td style="border:4px solid #20293A;border-radius:20px;padding:32px">
                
                            <img src="data:image/png;base64,{Convert.ToBase64String(big_img)}"
                                 alt="Convox"
                                 width="140"
                                 style="display:block;margin:0 auto 35px">
                
                            <p style="font-size:17px;font-weight:bold">
                                Hi {username},
                            </p>
                
                            <p style="font-size:14px;line-height:20px">
                                We received a request to reset the password for your Convox account.<br>
                                Your one-time verification code is:
                            </p>
                
                            <table align="center" cellpadding="0" cellspacing="0"
                                   style="margin:20px auto">
                                <tr>
                                    <td style="
                                        padding:12px 35px;
                                        background:rgba(134,153,255,0.77);
                                        border-radius:10px;
                                        font-size:24px;
                                        width:212px;
                                        height:54px;">
                                        {code}
                                    </td>
                                </tr>
                            </table>
                
                            <p style="font-size:13px;line-height:19px">
                                <strong>Note:</strong>
                                This code is valid for <strong>5 minutes.</strong><br>
                                Never share this code with anyone, including Convox staff.
                            </p>
                
                        </td>
                    </tr>
                
                    <tr>
                        <td style="padding-top:25px;font-size:13px;line-height:19px">
                
                            <p>
                                If you didn't request a password reset, you can safely ignore this email. <br>
                                Your password will remain unchanged and your account stays secure.
                            </p>
                
                            <p style="margin:25px 0">
                                Best regards,<br>
                                <strong>The Convox Team</strong>
                            </p>
                
                            <img src="data:image/png;base64,{Convert.ToBase64String(footer_img)}"
                                 alt="Convox"
                                 width="110"
                                 style="display:block">
                
                        </td>
                    </tr>
                
                </table>
                
                </td>
                </tr>
                </table>
                
                </body>
                </html>
                """;

            return body;

        }
    }

}
