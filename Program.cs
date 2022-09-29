using Microsoft.AspNetCore.Mvc;
using SingleSignONSAMLResponse.Interfaces;
using SingleSignONSAMLResponse.Request;
using SingleSignONSAMLResponse.Service;
using SingleSignONSAMLResponse.SingleSignOn;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddTransient<ISingleSignOnService, SingleSignOnService>();

builder.Services.Configure<SingleSignOnConfiguration>(builder.Configuration.GetSection("SingleSignOn"));


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapGet("/EncodedSamlResponse", (ISingleSignOnService singleSignOnService) =>
{
    return singleSignOnService.BuildEncodedSamlResponse();
}).WithName("EncodedSamlResponse");

app.MapPost("/DecodedSamlResponse", (ISingleSignOnService singleSignOnService, [FromBody] DecodeSamlResponseRequest request) =>
{
    return singleSignOnService.DecodeSamlResponse(request.SamlToken);
}).WithName("DecodedSamlResponse");

app.MapPost("/ValidateSignature", (ISingleSignOnService singleSignOnService, [FromBody] DecodeSamlResponseRequest request) =>
{
    return singleSignOnService.ValidateSamlAssertationSignature(request.SamlToken);
}).WithName("ValidateSignature");

app.Run();