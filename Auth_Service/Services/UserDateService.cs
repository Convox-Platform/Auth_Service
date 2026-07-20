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

        public UserDateService(DbConnection db) => _db = db;
    }

}
