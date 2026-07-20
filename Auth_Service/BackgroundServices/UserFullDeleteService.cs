using Auth_Service.Models;
using Dapper;
using Grpc.Net.Client;
using Grpc.Net.Client.Web;
using Mail.V1;
using System.Data;
using System.Data.Common;

namespace Auth_Service.BackgroundServices
{
    public class UserFullDeleteService:BackgroundService
    {
        private readonly DbConnection _db;
        private readonly string _mail_service_url;
        private readonly  MailService.MailServiceClient _client;
        private readonly GrpcChannel _channel;

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            using var timer = new PeriodicTimer(TimeSpan.FromHours(1));

            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                try
                {
                    await CheckUserDeleteTime();
                }
                catch (Exception ex)
                {
                    throw;
                }
            }
        }

        private async Task CheckUserDeleteTime()
        {
            string sqlselect = $"Select * FROM users Where Delete_At IS NOT NULL AND Delete_At < CURRENT_TIMESTAMP";

            var Users = await _db.QueryAsync<User>(sqlselect);

            
            foreach (var user in Users) {
                string sqldelete = $"DELETE FROM users WHERE id = {user.Id}";
                await _db.ExecuteAsync(sqldelete);

                await _client.SendEmailAsync(new SendEmailRequest { RecipientEmail = user.Email, Body= "Your account has been deleted" });
            }


        }

        public UserFullDeleteService(DbConnection db, [FromKeyedServices("mail_service_url")] string mail_service_url)
        {
            _db = db;
            _mail_service_url = mail_service_url;
           _channel = GrpcChannel.ForAddress(_mail_service_url, new GrpcChannelOptions
            {
                HttpHandler = new GrpcWebHandler(GrpcWebMode.GrpcWeb, new SocketsHttpHandler()),
                DisposeHttpClient = true
            });

            _client = new MailService.MailServiceClient(_channel);
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            
            await base.StopAsync(cancellationToken);
        }
        public override void Dispose()
        {
            _channel.Dispose();
        }
    }
}
