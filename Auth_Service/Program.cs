using Auth_Service.Models;
using Auth_Service.Services;
using Dapper;
using DbUp;
using DotNetEnv;
using Google.Apis.Auth;
using Google.Apis.Auth.OAuth2.Requests;
using Google.Apis.Auth.OAuth2.Responses;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using System.Data;
using System.Data.Common;
using System.Reflection;

namespace Auth_Service
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Env.Load();
            string? GCI = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID");
            var constr = Environment.GetEnvironmentVariable("CONNECTION_STRING");
            var origin = Environment.GetEnvironmentVariable("ORIGIN");

            var reflectionEnabled = true;
            if (bool.TryParse(Environment.GetEnvironmentVariable("GRPC_REFLECTION_ENABLED"), out var reflectionEnabledOverride))
            {
                reflectionEnabled = reflectionEnabledOverride;
            }

            EnsureDatabase.For.SqlDatabase(constr);
            var upgrader = DeployChanges.To
                .SqlDatabase(constr)
                .WithScriptsEmbeddedInAssembly(Assembly.GetExecutingAssembly())
                .LogToConsole()
                .Build();

            var migrationResult = upgrader.PerformUpgrade();
            if (!migrationResult.Successful)
            {
                Console.WriteLine(migrationResult.Error);
                throw migrationResult.Error;
            }

            var builder = WebApplication.CreateBuilder(args);
            builder.Services.AddCors(option =>
            {
                option.AddDefaultPolicy(policy =>
                {
                    policy.WithOrigins(origin ?? "http://localhost:5173").AllowAnyHeader().AllowAnyMethod()
                    .WithExposedHeaders("Grpc-Status", "Grpc-Message", "Grpc-Encoding", "Grpc-Accept-Encoding");
                });
            });
            // Add services to the container.
            builder.Services.AddGrpc();
            if (reflectionEnabled)
            {
                builder.Services.AddGrpcReflection();
            }

            builder.Services.AddTransient<DbConnection>(sp => new SqlConnection(constr));
            // GoogleAuthService залежить від System.Data.IDbConnection (JWTAuthService — від DbConnection).
            builder.Services.AddTransient<IDbConnection>(sp => new SqlConnection(constr));
            builder.Services.AddTransient<IdGen.IdGenerator>(sp => new IdGen.IdGenerator(0));
            builder.Services.AddHttpClient();

            var app = builder.Build();


            app.MapGet("/", () => "Communication with gRPC endpoints must be made through a gRPC client. To learn how to create a client, visit: https://go.microsoft.com/fwlink/?linkid=2086909");
            app.UseRouting();
            app.UseCors();

            app.UseGrpcWeb();

            app.MapGrpcService<JWTAuthService>().EnableGrpcWeb();
            app.MapGrpcService<GoogleAuthService>().EnableGrpcWeb();

            if (reflectionEnabled)
            {
                app.MapGrpcReflectionService();
            }
            Console.WriteLine("Server started!!!");
            app.Run();


        }
    }
}
