using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TodoApi;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddDbContext<ToDoDbContext>();
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader());
});

var jwtKey = builder.Configuration["Jwt:Key"];
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey!))
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseCors("AllowAll");
app.UseAuthentication();
app.UseAuthorization();
app.UseSwagger();
app.UseSwaggerUI();

// הרשמה
app.MapPost("/register", (ToDoDbContext db, User user) =>
{
    var exists = db.Users.Any(u => u.Username == user.Username);
    if (exists) return Results.BadRequest("משתמש כבר קיים");
    db.Users.Add(user);
    db.SaveChanges();
    return Results.Ok("נרשמת בהצלחה");
});

// התחברות
app.MapPost("/login", (ToDoDbContext db, User loginUser) =>
{
    var user = db.Users.FirstOrDefault(u =>
        u.Username == loginUser.Username &&
        u.Password == loginUser.Password);

    if (user is null) return Results.Unauthorized();

    var claims = new[]
    {
        new Claim(ClaimTypes.Name, user.Username!),
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
    };

    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey!));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var token = new JwtSecurityToken(
        issuer: builder.Configuration["Jwt:Issuer"],
        audience: builder.Configuration["Jwt:Audience"],
        claims: claims,
        expires: DateTime.Now.AddHours(1),
        signingCredentials: creds
    );

    return Results.Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
});

// פונקציה עזר — שולפת את ה-UserId מתוך ה-Token
int GetUserId(HttpContext context)
{
    var claim = context.User.FindFirst(ClaimTypes.NameIdentifier);
    return int.Parse(claim!.Value);
}

// GET — רק המשימות של המשתמש המחובר
app.MapGet("/items", (ToDoDbContext db, HttpContext context) =>
{
    var userId = GetUserId(context);
    return db.Items.Where(i => i.UserId == userId).ToList();
}).RequireAuthorization();

// POST — הוספת משימה עם UserId של המשתמש המחובר
app.MapPost("/items", (ToDoDbContext db, HttpContext context, Item item) =>
{
    item.UserId = GetUserId(context);
    db.Items.Add(item);
    db.SaveChanges();
    return Results.Created($"/items/{item.Id}", item);
}).RequireAuthorization();

// PUT — עדכון רק אם המשימה שייכת למשתמש
app.MapPut("/items/{id}", (ToDoDbContext db, HttpContext context, int id, Item updatedItem) =>
{
    var userId = GetUserId(context);
    var item = db.Items.FirstOrDefault(i => i.Id == id && i.UserId == userId);
    if (item is null) return Results.NotFound();
    item.Name = updatedItem.Name;
    item.IsComplete = updatedItem.IsComplete;
    db.SaveChanges();
    return Results.Ok(item);
}).RequireAuthorization();

// DELETE — מחיקה רק אם המשימה שייכת למשתמש
app.MapDelete("/items/{id}", (ToDoDbContext db, HttpContext context, int id) =>
{
    var userId = GetUserId(context);
    var item = db.Items.FirstOrDefault(i => i.Id == id && i.UserId == userId);
    if (item is null) return Results.NotFound();
    db.Items.Remove(item);
    db.SaveChanges();
    return Results.NoContent();
}).RequireAuthorization();

app.Run();