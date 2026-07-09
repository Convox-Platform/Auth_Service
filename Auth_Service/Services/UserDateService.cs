using Google.Protobuf.WellKnownTypes;
using Grpc.Core;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using UserDate_Service;

namespace Auth_Service.Services
{
    public class UserDateService: UserDate.UserDateBase
    {
        [Authorize]
        public override async Task<UserDateResponse> GetUserId(Empty request, ServerCallContext context)
        {
            var httpContext = context.GetHttpContext();
            var userId = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
            return new UserDateResponse { UserId = userId };
        }
    }
}
