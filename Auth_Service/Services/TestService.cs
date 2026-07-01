using Google.Protobuf.WellKnownTypes;
using Grpc.Core;

namespace Auth_Service.Services
{
    public class TestService:Tester.TesterBase
    {
        public override  Task<TestReply> GetMessage(TestRequest request, ServerCallContext context)
        {
            var res = request.FirstName + " " + request.LastName + " is " + request.Age + " years old.";

            return Task.FromResult(new TestReply
            {
                Message = res
            });
        }
        public override Task<TestReplyList> GetMessages(Empty request, ServerCallContext context)
        {
            var p1 = new TestReply
            {
                Message = "Hello"
            };
            var p2 = new TestReply
            {
                Message = "World"
            };
            var p3 = new TestReply
            {
                Message = "!"
            };
            var p4 = new TestReply
            {
                Message = "THis is a array"
            };
            var res = new TestReplyList();
            res.TestReplies.Add(p1); res.TestReplies.Add(p2); res.TestReplies.Add(p3); res.TestReplies.Add(p4);
            return Task.FromResult(res);
        }
    }
    
}
