using Dapper;
using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
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

        public UserDateService(DbConnection db) => _db = db;
    }

}
