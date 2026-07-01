using Auth_Service.Models;
using Auth_Service.Services;
using Dapper;
using DotNetEnv;
using Google.Apis.Auth;
using Google.Apis.Auth.OAuth2.Requests;
using Google.Apis.Auth.OAuth2.Responses;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using System.Data;
using System.Data.Common;

namespace Auth_Service
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Env.Load();
            string? GCI = Environment.GetEnvironmentVariable("Google_client_id");
            var constr = Environment.GetEnvironmentVariable("CONNECTION_STRING");

            var builder = WebApplication.CreateBuilder(args);
            builder.Services.AddCors(option =>
            {
                option.AddDefaultPolicy(policy =>
                {
                    policy.WithOrigins("http://localhost:5173").AllowAnyHeader().AllowAnyMethod()
                    .WithExposedHeaders("Grpc-Status", "Grpc-Message", "Grpc-Encoding", "Grpc-Accept-Encoding"); 
                });
            });
            // Add services to the container.
            builder.Services.AddGrpc();
            builder.Services.AddGrpcReflection();

            builder.Services.AddTransient<DbConnection>(sp => new SqlConnection(constr));
            builder.Services.AddTransient<IdGen.IdGenerator>(sp => new IdGen.IdGenerator(0));
            builder.Services.AddHttpClient();

            var app = builder.Build();
           

            app.MapGet("/", () => "Communication with gRPC endpoints must be made through a gRPC client. To learn how to create a client, visit: https://go.microsoft.com/fwlink/?linkid=2086909");
            app.UseRouting();
            app.UseCors();
            
            app.UseGrpcWeb();

            app.MapGrpcService<TestService>();
            app.MapGrpcService<JWTAuthService>().EnableGrpcWeb();
            app.MapGrpcService<GoogleAuthService>().EnableGrpcWeb();

            app.MapGrpcReflectionService();
            Console.WriteLine("Server started!!!");
            app.Run();
            

        }
    }
}