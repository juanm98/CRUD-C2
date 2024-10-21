using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Security.Claims;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Mi API con JWT", Version = "v1" });

    // Configuración para agregar el token JWT en Swagger
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Introduzca 'Bearer' [espacio] seguido de su token JWT."
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});
builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {            
            ValidateIssuer = true, 
            ValidateAudience = true,
            ValidateLifetime = true, 
            ValidateIssuerSigningKey = true, 
            ValidIssuer = "yourdomain.com", 
            ValidAudience = "yourdomain.com",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("vainitaOMGclavelargaysegura_a234243423423awda"))
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseMiddleware<MyMiddleware>();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization(); 


// Función para generar el JWT
string GenerateJwtToken()
{
    var claims = new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, "test"),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim("User","Mi usuario")
    };

    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("vainitaOMGclavelargaysegura_a234243423423awda"));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
        issuer: "yourdomain.com",
        audience: "yourdomain.com",
        claims: claims,
        expires: DateTime.Now.AddMinutes(30),
        signingCredentials: creds);

    return new JwtSecurityTokenHandler().WriteToken(token);
};

// Endpoint de login para generar el JWT
app.MapPost("/login", (UserLogin login) =>
{
    if (login.Username == "test" && login.Password == "pass") // Validar credenciales
    {
        var token = GenerateJwtToken();
        return Results.Ok(new { token });
    }
    return Results.Unauthorized();
});

var companies = new List<Company>
{
    new Company { Id = 1, Name = "Coca Cola" },
    new Company { Id = 2, Name = "Pepsi" }
};

var employees = new List<Employee>
{
    new Employee { Id = 1, Name = "Juan", Position = "Frontend", Salary = "2000USD", CompanyId = 1 },
    new Employee { Id = 2, Name = "Jose", Position = "Backend", Salary = "3000USD", CompanyId = 2 }
};

var articles = new List<Article>
{
    new Article { Id = 1, Name = "Cola Cola", Value = 5, CompanyId = 1 },
    new Article { Id = 2, Name = "Pepsi", Value = 6, CompanyId = 1 },
    new Article { Id = 3, Name = "Sprite", Value = 4, CompanyId = 2 },
    new Article { Id = 4, Name = "Agua", Value = 2, CompanyId = 2 }
};

var orders = new List<Order>
{
    new Order { Id = 1, Name = "Order 1", EmployeeId = 1, TotalValue = 10, Status = "pending", ArticleIds = new List<int> { 1, 2 } },
    new Order { Id = 2, Name = "Order 2", EmployeeId = 2, TotalValue = 15, Status = "pending", ArticleIds = new List<int> { 3, 4 } }
};

var invoices = new List<Invoice>();

int invoiceIdCounter = 0;

int employeeIdCounter = employees.Max(e => e.Id);

// CRUD de Company
app.MapGet("/Company", () =>
{
    return Results.Ok(companies);
}).RequireAuthorization();

// Company por Id
app.MapGet("/Company/{Id}", (int Id) =>
{
    var company = companies.FirstOrDefault(p => p.Id == Id);
    return company != null ? Results.Ok(company) : Results.NotFound();
}).RequireAuthorization();

// Crear un Company
app.MapPost("/Company", (Company newCompany) =>
{
    // Asigna nuevo id incrementando el maximo actual
    newCompany.Id = companies.Max(p => p.Id) + 1;
    // Ahora añade  la nueva company a la lista
    companies.Add(newCompany);
    // Retorna 201 created con la ubicacion del nuevo recurso
    return Results.Created($"/Company/{newCompany.Id}", newCompany);
}).RequireAuthorization();

// Update de company
app.MapPut("/Company/{Id}", (int Id, Company updatedCompany) =>
{
    // Primero lo busca por Id
    var company = companies.FirstOrDefault(p => p.Id == Id);
    if (company == null)
    {
        return Results.NotFound();
    }
    // Actualiza el nombre de la company
    company.Name = updatedCompany.Name;
    return Results.NoContent();
}).RequireAuthorization();

// Delete company by id
app.MapDelete("/Company/{Id}", (int Id) =>
{
    var company = companies.FirstOrDefault(c => c.Id == Id);
    if (company is null) return Results.NotFound();

    var hasEmployees = employees.Any(e => e.CompanyId == Id);
    if (hasEmployees)
        return Results.BadRequest("No se puede eliminar empresa porque tiene empleados.");

    companies.Remove(company);
    return Results.NoContent();
}).RequireAuthorization();

// CRUD de Employees
app.MapGet("/employees", () => employees).RequireAuthorization();

// Empleado por id
app.MapGet("/employees/{id}", (int id) =>
{
    var employee = employees.FirstOrDefault(e => e.Id == id);
    return employee is not null ? Results.Ok(employee) : Results.NotFound();
}).RequireAuthorization();

// Crea empleado
app.MapPost("/employees", (Employee employee) =>
{
    // Asigna un nuevo id incrementado el contador
    employee.Id = ++employeeIdCounter;
    employees.Add(employee);
    return Results.Created($"/employees/{employee.Id}", employee);
}).RequireAuthorization();

// Actualiza el empleado
app.MapPut("/employees/{id}", (int id, Employee updatedEmployee) =>
{
    // Busca por id
    var employee = employees.FirstOrDefault(e => e.Id == id);
    if (employee is null) return Results.NotFound();

    // Actualiza las propiedades del empleado
    employee.Name = updatedEmployee.Name;
    employee.CompanyId = updatedEmployee.CompanyId;
    // Y retorna el emp actualizado
    return Results.Ok(employee);
}).RequireAuthorization();

// Delete de empleado por id
app.MapDelete("/employees/{id}", (int id) =>
{
    // Busca el empleado por id 
    var employee = employees.FirstOrDefault(e => e.Id == id);
    if (employee is null) return Results.NotFound();

    employees.Remove(employee);
    return Results.NoContent();
}).RequireAuthorization();


int articleIdCounter = articles.Max(a => a.Id);

// CRUD de Articles
app.MapGet("/articles", () =>
{
    return Results.Ok(articles);
}).RequireAuthorization();

app.MapGet("/articles/{id}", (int id) =>
{
    var article = articles.FirstOrDefault(a => a.Id == id);
    return article is not null ? Results.Ok(article) : Results.NotFound();
}).RequireAuthorization();

app.MapPost("/articles", (Article newArticle) =>
{
    // Checkea si la company existe
    var companyExists = companies.Any(c => c.Id == newArticle.CompanyId);
    if (!companyExists)
    {
        return Results.BadRequest("Esta compañía no existe");
    }

    // Asigna un nuevo id
    newArticle.Id = ++articleIdCounter;
    articles.Add(newArticle);
    return Results.Created($"/articles/{newArticle.Id}", newArticle);
}).RequireAuthorization();

// Actualiza un articulo existente
app.MapPut("/articles/{id}", (int id, Article updatedArticle) =>
{
    // Busca el articulo a actualizar
    var article = articles.FirstOrDefault(a => a.Id == id);
    if (article is null) return Results.NotFound();

    // Checkea si la company existe
    var newCompanyExists = companies.Any(c => c.Id == updatedArticle.CompanyId);
    if (!newCompanyExists)
    {
        return Results.BadRequest("Esta compañía no existe");
    }
    
    // Actualiza las propiedades del articulo
    article.Name = updatedArticle.Name;
    article.Value = updatedArticle.Value;
    article.CompanyId = updatedArticle.CompanyId;

    return Results.Ok(article);
}).RequireAuthorization();

app.MapDelete("/articles/{id}", (int id) =>
{
    var article = articles.FirstOrDefault(a => a.Id == id);
    if (article is null) return Results.NotFound();

    articles.Remove(article);
    return Results.NoContent();
}).RequireAuthorization();

// Endpoint adicional para obtener artículos con la compañia 
app.MapGet("/companies/{companyId}/articles", (int companyId) =>
{
    var companyArticles = articles.Where(a => a.CompanyId == companyId).ToList();
    return Results.Ok(companyArticles);
}).RequireAuthorization();

int orderIdCounter = orders.Max(o => o.Id);

// CRUD de Orders
app.MapGet("/orders", () =>
{
    return Results.Ok(orders);
}).RequireAuthorization();

app.MapGet("/orders/{id}", (int id) =>
{
    var order = orders.FirstOrDefault(o => o.Id == id);
    return order is not null ? Results.Ok(order) : Results.NotFound();
}).RequireAuthorization();

app.MapPost("/orders", (OrderInput newOrder) =>
{
    // Checkea si el employee existe
    var employee = employees.FirstOrDefault(e => e.Id == newOrder.EmployeeId);
    if (employee == null)
    {
        return Results.BadRequest("El empleado no existe");
    }

    // Checkea si hay un articulo
    if (newOrder.ArticleIds.Count == 0)
    {
        return Results.BadRequest("La orden debe tener como minimo un articulo");
    }

    // Checkea si todos los articulos existen y pertenecen a la misma compañia que el empleado
    var orderArticles = articles.Where(a => newOrder.ArticleIds.Contains(a.Id)).ToList();
    // verifica si alguno de los artículos en el pedido pertenece a una empresa diferente 
    if (orderArticles.Count != newOrder.ArticleIds.Count || orderArticles.Any(a => a.CompanyId != employee.CompanyId))
    {
        return Results.BadRequest("Uno o mas articulos no existen o no pertenecen a la misma empresa del empleado");
    }

    // Calcula el valor total
    var totalValue = orderArticles.Sum(a => a.Value);

    var order = new Order
    {
        Id = ++orderIdCounter,
        Name = newOrder.Name,
        EmployeeId = newOrder.EmployeeId,
        TotalValue = totalValue,
        Status = "pending",
        ArticleIds = newOrder.ArticleIds
    };

    orders.Add(order);
    return Results.Created($"/orders/{order.Id}", order);
}).RequireAuthorization();

app.MapPut("/orders/{id}", (int id, OrderInput updatedOrder) =>
{
    var order = orders.FirstOrDefault(o => o.Id == id);
    if (order is null) return Results.NotFound();

    // Checkea si el employee existe
    var employee = employees.FirstOrDefault(e => e.Id == updatedOrder.EmployeeId);
    if (employee == null)
    {
        return Results.BadRequest("El empleado no existe");
    }

    // Checkea si hay un articulo
    if (updatedOrder.ArticleIds.Count == 0)
    {
        return Results.BadRequest("El pedido debe tener al menos un articulo");
    }

    // Checkea si todos los articulos existen y pertenecen a la misma empresa que el empleado
    var orderArticles = articles.Where(a => updatedOrder.ArticleIds.Contains(a.Id)).ToList();
    if (orderArticles.Count != updatedOrder.ArticleIds.Count || orderArticles.Any(a => a.CompanyId != employee.CompanyId))
    {
        return Results.BadRequest("Uno o mas articulos no existen o no pertenecen a la misma empresa del empleado");
    }

    // Calcula un nuevo total
    var totalValue = orderArticles.Sum(a => a.Value);

    order.Name = updatedOrder.Name;
    order.EmployeeId = updatedOrder.EmployeeId;
    order.TotalValue = totalValue;
    order.ArticleIds = updatedOrder.ArticleIds;

    return Results.Ok(order);
}).RequireAuthorization();

app.MapDelete("/orders/{id}", (int id) =>
{
    var order = orders.FirstOrDefault(o => o.Id == id);
    if (order is null) return Results.NotFound();

    if (order.Status == "pending")
    {
        return Results.BadRequest("No se puede eliminar un pedido pendiente");
    }

    orders.Remove(order);
    return Results.NoContent();
}).RequireAuthorization();

// Endpoint para cambiar el estado de un pedido y generar factura
app.MapPut("/orders/{id}/complete", (int id) =>
{
    var order = orders.FirstOrDefault(o => o.Id == id);
    if (order is null) return Results.NotFound();

    if (order.ArticleIds.Count == 0)
    {
        return Results.BadRequest("No se puede completar un pedido sin articulos");
    }

    if (order.Status == "completed")
    {
        return Results.BadRequest("La orden ya esta completada");
    }

    order.Status = "completed";

    // Genera factura
    var newInvoice = new Invoice
    {
        Id = ++invoiceIdCounter,
        OrderId = order.Id,
        Status = "pending",
        EstimatedDeliveryDate = DateTime.Now.AddDays(7),
        TotalValue = order.TotalValue
    };

    invoices.Add(newInvoice);

    return Results.Ok(new { Order = order, Invoice = newInvoice });
}).RequireAuthorization();

// Endpoint para recibir pedidos por empleado
app.MapGet("/employees/{employeeId}/orders", (int employeeId) =>
{
    var employeeOrders = orders.Where(o => o.EmployeeId == employeeId).ToList();
    return Results.Ok(employeeOrders);
}).RequireAuthorization();

// CRUD de Invoices
app.MapGet("/invoices", () =>
{
    return Results.Ok(invoices);
}).RequireAuthorization();

app.MapGet("/invoices/{id}", (int id) =>
{
    var invoice = invoices.FirstOrDefault(f => f.Id == id);
    return invoice is not null ? Results.Ok(invoice) : Results.NotFound();
}).RequireAuthorization();

app.MapPut("/invoices/{id}/status", (int id, string newStatus) =>
{
    var invoice = invoices.FirstOrDefault(f => f.Id == id);
    if (invoice is null) return Results.NotFound();

    if (newStatus != "pending" && newStatus != "paid")
    {
        return Results.BadRequest("El status de la orden debe decir 'pending' o 'paid'.");
    }

    invoice.Status = newStatus;
    return Results.Ok(invoice);
}).RequireAuthorization();

// Endpoint para obtener facturas por pedido
app.MapGet("/orders/{orderId}/invoice", (int orderId) =>
{
    var invoice = invoices.FirstOrDefault(f => f.OrderId == orderId);
    return invoice is not null ? Results.Ok(invoice) : Results.NotFound();
}).RequireAuthorization();

// Middleware personalizado
app.UseWhen(context => context.Request.Path.StartsWithSegments("/theone"), (appBuilder) =>
{
    appBuilder.Use(async (context, next) =>
    {                
        if (context.Request.Headers.ContainsKey("Key") && context.Request.Headers["Key"].ToString() == "vainitaOMG")
        {                        
            await next();
        }
        else
        {           
            context.Response.StatusCode = 400; 
            await context.Response.WriteAsync("Falta el header X-Custom-Header.");
        }
    });
});

// Endpoint protegido
app.MapGet("/theone", () =>
{
    return Results.Ok("Este es un endpoint seguro");
});

app.Run();


// Modelos
public class Company
{
    public int Id { get; set; }
    public string Name { get; set; }
}

public class Employee
{
    public int Id { get; set; }
    public string Name { get; set; }
    public string Position { get; set; }
    public string Salary { get; set; }
    public int CompanyId { get; set; }
}

public class Article
{
    public int Id { get; set; }
    public string Name { get; set; }
    public decimal Value { get; set; }
    public int CompanyId { get; set; }
}

public class Order
{
    public int Id { get; set; }
    public string Name { get; set; }
    public int EmployeeId { get; set; }
    public decimal TotalValue { get; set; }
    public string Status { get; set; }
    public List<int> ArticleIds { get; set; } = new List<int>();
}

public class OrderInput
{
    public string Name { get; set; }
    public int EmployeeId { get; set; }
    public List<int> ArticleIds { get; set; } = new List<int>();
}

public class Invoice
{
    public int Id { get; set; }
    public int OrderId { get; set; }
    public string Status { get; set; }
    public DateTime EstimatedDeliveryDate { get; set; }
    public decimal TotalValue { get; set; }
}

public class UserLogin
{
    public string Username { get; set; }
    public string Password { get; set; }
}

public class MyMiddleware
{
    private readonly RequestDelegate _next;

    public MyMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task Invoke(HttpContext context)
    {
        await _next(context);
        Console.WriteLine("-------------------->Me comio lo del SQL server<------------------------");
    }
}
