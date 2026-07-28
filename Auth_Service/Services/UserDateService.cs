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
using UserDate_Service;

namespace Auth_Service.Services
{
    public class UserDateService: UserDate.UserDateBase
    {
        private readonly DbConnection _db;
        private ConfirmationStore _confirmationStore;
        private readonly string _mailServiceUrl;

        [Authorize]
        public override async Task<UserDateResponse> GetUserId(Empty request, ServerCallContext context)
        {
            var httpContext = context.GetHttpContext();
            var userId = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
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
            using var channel = GrpcChannel.ForAddress("https://localhost:5001", new GrpcChannelOptions { HttpHandler = grpcWebHandler });

            var userid = context.GetHttpContext().User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (userid == request.UserId)
            {
                var client = new MailService.MailServiceClient(channel);
                var sql = """
                    UPDATE users 
                    SET delete_at = now() + interval '1 day' 
                    WHERE id = @Id;
                    """;// 1 день только на время, а вообще должно быть 14 дней

                await _db.ExecuteAsync(sql, new { Id = request.UserId });

                var sqlUser = """
                    SELECT email FROM users WHERE id = @Id;
                    """;
                var email = await _db.QueryFirstOrDefaultAsync<string>(sqlUser, new { Id = request.UserId });

                await client.SendEmailAsync(new SendEmailRequest { RecipientEmail = email, Body = "Your account will be deleted in 14 days" });

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
            
            string code = Random.Shared.Next(100000, 999999).ToString("D8");

            var Handler = new GrpcWebHandler(GrpcWebMode.GrpcWeb, new SocketsHttpHandler());
            var channel = GrpcChannel.ForAddress(_mailServiceUrl, new GrpcChannelOptions { HttpHandler = Handler });

            var client = new MailService.MailServiceClient(channel);

            await client.SendEmailAsync(new SendEmailRequest { RecipientEmail = request.Email, Body = $"Your verification code is {code}" });

            var operationId = _confirmationStore.CreateWithEmail(request.Email, code);// запись в кеш

            return new OperIdResponce { OperId = operationId };
        }

        public override async Task<UserDateBoolResponse> CheckChangePasswordCode(PasswordCodeReqest request, ServerCallContext context)
        {
            _confirmationStore.TryGet(request.OperId, out var confirmation);


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

            string sqlUpdate = "UPDATE users SET password_hash = @hash WHERE Id = @id";
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

            string sqlUpdate = "UPDATE users SET password_hash = @hash WHERE id = @id";
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

            string sqlUpdate = "UPDATE users SET password_hash = @hash WHERE id = @id";
            var hash = BCrypt.Net.BCrypt.HashPassword(request.Password);
            await _db.ExecuteAsync(sqlUpdate, new { hash = hash, id = request.UserId });

            return new UserDateBoolResponse { IsExist = true };


        }

        public UserDateService(DbConnection db, ConfirmationStore confirmationStore, [FromKeyedServices("mail_service_url")] string mailServiceUrl)
        {
            _db = db;
            _confirmationStore = confirmationStore;
            _mailServiceUrl = mailServiceUrl;
        }
    }

}
