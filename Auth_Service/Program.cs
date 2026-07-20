using Auth_Service.Models;
using Auth_Service.Services;
using Dapper;
using DbUp;
using DotNetEnv;
using Google.Apis.Auth;
using Google.Apis.Auth.OAuth2.Requests;
using Google.Apis.Auth.OAuth2.Responses;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using System.Data;
using System.Data.Common;
using System.Reflection;
using System.Text;

namespace Auth_Service
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Env.Load();
            var googleClientId = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_ID")
                ?? throw new ArgumentNullException("GOOGLE_CLIENT_ID not found");
            var googleClientSecret = Environment.GetEnvironmentVariable("GOOGLE_CLIENT_SECRET")
                ?? throw new ArgumentNullException("GOOGLE_CLIENT_SECRET not found");
            var googleRedirectUris = Environment.GetEnvironmentVariable("GOOGLE_REDIRECT_URIS")
                ?? Environment.GetEnvironmentVariable("REDIRECT_URI")
                ?? throw new ArgumentNullException("GOOGLE_REDIRECT_URIS or REDIRECT_URI not found");
            var constr = Environment.GetEnvironmentVariable("CONNECTION_STRING")?? throw new ArgumentNullException("CONNECTION_STRING not found");
            var allowedOrigins = Environment.GetEnvironmentVariable("ORIGINS")
                ?? Environment.GetEnvironmentVariable("ORIGIN")
                ?? throw new ArgumentNullException("ORIGINS or ORIGIN not found");
            var origins = allowedOrigins
                .Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (origins.Length == 0)
                throw new ArgumentException("At least one allowed origin must be configured.");
            var user_service_url = Environment.GetEnvironmentVariable("USER_SERVICE_URL") ?? throw new ArgumentNullException("USER_SERVICE_URL not found");
            var mail_service_url = Environment.GetEnvironmentVariable("MAIL_SERVICE_URL") ?? throw new ArgumentNullException("MAIL_SERVICE_URL not found");

            var secret = Environment.GetEnvironmentVariable("JWT_SECRET") ?? throw new ArgumentNullException("JWT_SECRET not found");
            var reflectionEnabled = true;


            if (bool.TryParse(Environment.GetEnvironmentVariable("GRPC_REFLECTION_ENABLED"), out var reflectionEnabledOverride))
            {
                reflectionEnabled = reflectionEnabledOverride;
            }

            EnsureDatabase.For.PostgresqlDatabase(constr);
            var upgrader = DeployChanges.To
                .PostgresqlDatabase(constr)
                .WithScriptsEmbeddedInAssembly(Assembly.GetExecutingAssembly())
                .LogToConsole()
                .Build();

            var migrationResult = upgrader.PerformUpgrade();
            if (!migrationResult.Successful)
            {
                Console.WriteLine(migrationResult.Error);
            }

            var builder = WebApplication.CreateBuilder(args);
            builder.Services.AddCors(option =>
            {
                option.AddDefaultPolicy(policy =>
                {
                    policy.WithOrigins(origins).AllowAnyHeader().AllowAnyMethod()
                    .WithExposedHeaders("Grpc-Status", "Grpc-Message", "Grpc-Encoding", "Grpc-Accept-Encoding");
                });
            });

            builder.Services.AddAuthorization();
            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(option =>
            {
                option.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = false,
                    ValidateAudience = false,

                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
                 
                };
            });


            // Add services to the container.
            builder.Services.AddGrpc();
            if (reflectionEnabled)
            {
                builder.Services.AddGrpcReflection();
            }

            builder.Services.AddTransient<DbConnection>(sp => new NpgsqlConnection(constr));
            builder.Services.AddTransient<IdGen.IdGenerator>(sp => new IdGen.IdGenerator(0));
            
            builder.Services.AddKeyedSingleton<string>("user_service_url",(sp,key) => user_service_url ?? "http://localhost:5001");
            builder.Services.AddKeyedSingleton<string>("mail_service_url", (sp, key) => mail_service_url ?? "http://localhost:5002");

            builder.Services.AddKeyedSingleton<string>("secret_key",(sp,key) => secret ?? "secret");
            builder.Services.AddKeyedSingleton<string>("google_client_id", (sp, key) => googleClientId);
            builder.Services.AddKeyedSingleton<string>("google_client_secret", (sp, key) => googleClientSecret);
            builder.Services.AddKeyedSingleton<string>("google_redirect_uris", (sp, key) => googleRedirectUris);
            builder.Services.AddKeyedSingleton<string>("allowed_origins", (sp, key) => allowedOrigins);
            builder.Services.AddHttpClient();

            var app = builder.Build();


            app.MapGet("/", () => "Communication with gRPC endpoints must be made through a gRPC client. To learn how to create a client, visit: https://go.microsoft.com/fwlink/?linkid=2086909");
            app.UseRouting();
            app.UseCors();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseGrpcWeb();

            app.MapGrpcService<JWTAuthService>().EnableGrpcWeb();
            app.MapGrpcService<GoogleAuthService>().EnableGrpcWeb();
            app.MapGrpcService<UserDateService>().EnableGrpcWeb();

            if (reflectionEnabled)
            {
                app.MapGrpcReflectionService();
            }
            Console.WriteLine("Server started!!!");
            app.Run();


        }
    }
}
