using Azure.Core;
using Azure.Identity;
using E_Commerce.ApplicationDbContext;
using E_Commerce.Authentication;
using E_Commerce.Data;
using E_Commerce.JwtOptions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Conventions;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.Data.Common;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Security.Cryptography.Xml;
using System.Security.Principal;
using System.Text;

namespace E_Commerce.Controllers
{
    [ApiController]
    [Route("api/[Controller]")]
    [Authorize]
    public class E_CommerceController : ControllerBase
    {
        public E_CommerceController(ILogger<ControllerBase> logger, AppDbContext dbContext, jwtOptionsAttributes jwtOptions)
        {
            Logger = logger;
            DbContext = dbContext;
            JwtOptions = jwtOptions;
        }
        public ILogger<ControllerBase> Logger { get; }
        public AppDbContext DbContext { get; }
        public jwtOptionsAttributes JwtOptions { get; }

        [HttpPost("Register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register(Users users)
        {
            if (!ModelState.IsValid)
                return BadRequest("Enter True Or Valid Data");
            var ExistingUser = await DbContext.Users.FirstOrDefaultAsync(op => op.FName == users.FName && op.LName == users.LName);
            if (ExistingUser is null || !BCrypt.Net.BCrypt.Verify(users.Password, ExistingUser.Password))
                return NotFound("UserName[FName Or LName] Or Password");

            users.Password = BCrypt.Net.BCrypt.HashPassword(users.Password);
            await DbContext.Users.AddAsync(users);
            await DbContext.SaveChangesAsync();
            return Ok("Done!!");
        }

        [HttpPost("Login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login(AuthenticationRequest request)
        {
            var ExistingUser = await DbContext.Users.FirstOrDefaultAsync(op => op.FName == request.FName && op.LName == request.LName);
            if (ExistingUser is null || !BCrypt.Net.BCrypt.Verify(request.Password, ExistingUser.Password))
                return NotFound("UserName Or Password is InValid");

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = JwtOptions.Issuer,
                Audience = JwtOptions.Audience,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtOptions.SigningKey)),SecurityAlgorithms.Sha256),
                Subject = new System.Security.Claims.ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, request.FName),
                    new Claim(ClaimTypes.NameIdentifier, ExistingUser.UserID.ToString()),
                    new Claim(ClaimTypes.Role, "Customer"),
                    new Claim(ClaimTypes.Role, "Admin")
                } ) ,
                Expires = DateTime.UtcNow.AddMinutes(15)
            };
            var SecurityToken = tokenHandler.CreateToken(tokenDescriptor);

            var Accesstoken = tokenHandler.WriteToken(SecurityToken);
            Logger.LogCritical("something is InValid in LogIn API");
            var expirationDate = DateTime.UtcNow.AddDays(30);
            var attribute = new AccessTokenAttributes
            {
                accessToken = BCrypt.Net.BCrypt.HashString(Accesstoken),//. for any hacker can't deal with the database
                ExpireDate = expirationDate
            };
            await DbContext.Access.AddAsync(attribute);
            if (expirationDate > DateTime.UtcNow) //. this condition will be continue for Date of Expiration Date (30 days)
                return Ok($"AccessToken : `{attribute.accessToken}`,RefreshToken : `{attribute.RefreshToken}` ");
            else
                return BadRequest("Token Generation failed");
        }

        [HttpPost("LogOut")]
        [Authorize(Roles = "AdminManger,Client")]
        public async Task<IActionResult> LogOut()
        {
            var UserIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (UserIdClaim is null || int.TryParse(UserIdClaim, out int userid))
                return Unauthorized("You are not allowed to access");
            var AccessToken = await DbContext.Access.FirstOrDefaultAsync(op => op.UserID == userid);
            if (AccessToken != null)
            {
                DbContext.Access.Remove(AccessToken);
                await DbContext.SaveChangesAsync();
            }
            return Ok("Logged out Successfully");
        }
    }

    [ApiController]
    [Route("api/[Controller]")]
    [Authorize]
    public class UsersAPIs : ControllerBase
    {
        public UsersAPIs(AppDbContext dbContext, ILogger<UsersAPIs> logger)
        {
            DbContext = dbContext;
            Logger = logger;
        }

        public AppDbContext DbContext { get; }
        public ILogger<UsersAPIs> Logger { get; }

        [HttpGet("Users")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetUsers()
        {
            var ExistingUsers = await DbContext.Users.ToListAsync();
            return Ok(ExistingUsers);
        }

        [HttpGet("User")]
        [Authorize(Roles = "Admin,Customer")]
        public async Task<IActionResult> GetUserByID(int id)
        {
            var ExistingUser = await DbContext.Users.FirstOrDefaultAsync(op => op.UserID == id);
            if (ExistingUser is null)
                return NotFound($"User With ID : `{id}` is not Exist");
            return Ok(ExistingUser);
        }

        [HttpPut("Users/{id}")]
        [Authorize("Admin,Customer")]
        public async Task<IActionResult> UpdateUserInfo(int id, [FromBody] UpdateUserDTO userDTO)
        {
            var ExistingUser = await DbContext.Users.FirstOrDefaultAsync(op => op.UserID == id);
            if (ExistingUser is null)
                return NotFound("User is not exist");
            var currentId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value);
            var currentRole = User.FindFirst(ClaimTypes.Role)?.Value;
            if (currentRole != "Admin" && currentId != id)
                return Forbid("You are not allowed to change your role");

            if (currentRole != "Customer" && ExistingUser.Role != "Admin")
                return BadRequest("You are not allowed to change your role");

            ExistingUser.FName = userDTO.FName;
            ExistingUser.LName = userDTO.LName;
            ExistingUser.Email = userDTO.Email;
            ExistingUser.Role = userDTO.Role;
            if (!string.IsNullOrEmpty(userDTO.Password))
            {
                if (string.IsNullOrEmpty(userDTO.OldPassword))
                {
                    return BadRequest("First, Enter your Old Password");
                }
                if (!BCrypt.Net.BCrypt.Verify(userDTO.OldPassword, ExistingUser.Password))//.make sure on the Old password after the Client entered the Old password
                    return BadRequest("Invalid Old Password, Enter Valid Data");
                ExistingUser.Password = BCrypt.Net.BCrypt.HashPassword(userDTO.Password);
            }
            DbContext.Users.Update(ExistingUser);
            await DbContext.SaveChangesAsync();
            return Ok("Updated Successfully");
        }

        [HttpDelete("User/{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteUserByID(int id)
        {
            var ExistingUser = await DbContext.Users.FirstOrDefaultAsync(op => op.UserID == id);
            if (ExistingUser is null)
                return NotFound("Not Exist");
            DbContext.Users.Remove(ExistingUser);
            await DbContext.SaveChangesAsync();
            return Ok("User Removed Successfully");
        }
    }

    [ApiController]
    [Route("api/[Controller]")]
    [Authorize]
    public class Product : ControllerBase
    {
        public Product(ILogger<Product> logger, AppDbContext dbContext)
        {
            Logger = logger;
            DbContext = dbContext;
        }
        public ILogger<Product> Logger { get; }
        public AppDbContext DbContext { get; }

        [HttpGet("Products")]
        [Authorize(Roles = "Customer")]
        public async Task<IActionResult> GetProducts()
        {
            var ExistingProducts = await DbContext.Products.ToListAsync();
            return Ok(ExistingProducts);
        }

        [HttpGet("Product/{id}")]
        [Authorize(Roles = "Customer")]
        public async Task<IActionResult> GetProductByID(int id)
        {
            var ExistingProduct = await DbContext.Products.FirstOrDefaultAsync(op => op.ProductID == id);
            if (ExistingProduct is null)
                return NotFound("Not Exist!!");
            return Ok(ExistingProduct);
        }

        [HttpPost("Products")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> CreateProduct(Products pr)
        {
            if (!ModelState.IsValid)
                return BadRequest("Enter Valid Data");
            var ExistingProduct = await DbContext.Products.FirstOrDefaultAsync(op => op.ProductID == pr.ProductID && op.ProductName == pr.ProductName);
            if (ExistingProduct is not null)
                return BadRequest("this Product is already Exist");
            await DbContext.Products.AddAsync(ExistingProduct);
            await DbContext.SaveChangesAsync();
            return Ok("Done!");
        }

        [HttpPut("Products/{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> UpdateProductByID(int id, Products products)
        {
            var ExistingProducts = await DbContext.Products.FirstOrDefaultAsync(op => op.ProductID == id);
            if (ExistingProducts is null)
            {
                return NotFound("Not Exist!!");
            }
            ExistingProducts.ProductName = products.ProductName;
            ExistingProducts.Price = products.Price;
            ExistingProducts.Description = products.Description;
            ExistingProducts.Stock = products.Stock;

            DbContext.Products.Update(ExistingProducts);
            await DbContext.SaveChangesAsync();
            return Ok("Done!!");
        }

        [HttpDelete("Products/{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteByID(int id)
        {
            var ExistingProducts = await DbContext.Products.FirstOrDefaultAsync(op => op.ProductID == id);
            if (ExistingProducts is null)
                return NotFound($"Product with id : `{id}` is not Exist");
            DbContext.Products.Remove(ExistingProducts);
            await DbContext.SaveChangesAsync();
            return Ok("Done!!");
        }
    }
    [ApiController]
    [Route("api/[Controller]")]
    [Authorize]
    public class BasketAPIs : ControllerBase
    {

        public BasketAPIs(ILogger<Basket> logger, AppDbContext dbContext)
        {
            Logger = logger;
            DbContext = dbContext;
        }

        public ILogger<Basket> Logger { get; }
        public AppDbContext DbContext { get; }

        [HttpGet("BasketProducts")]
        [Authorize("Customer ")]
        public async Task<ActionResult<BasketDTO>> GetBasketUser()
        {
            int userid = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value);//UserId from AccessToken
            var ExistingBasket = DbContext.Baskets.Include(op => op.basketItems)
                .ThenInclude(bi => bi.Product).FirstOrDefault(op => op.UserID == userid);
            if (ExistingBasket is null)
                return NotFound("Not Exist");
            var BasketDTO = new BasketDTO
            {
                BasketID = ExistingBasket.ID,
                UserID = ExistingBasket.UserID,
                items = ExistingBasket.basketItems.Select(op => new BasketItemDTO
                {
                    ProductID = op.ProductID,
                    Quantity = op.Quantity,
                }).ToList()
            };
            return Ok(BasketDTO);
        }

        [HttpGet("Basket/{id}")]
        [Authorize(Roles = "Customer")]
        public async Task<ActionResult<BasketDTO>> GetBasketByID(int id)
        {
            //int userid = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value);
            //if (userid != id)
            //    return Unauthorized("Invalid UserID"); //. here i used UserId to bring Basket

            var existingBasket = DbContext.Baskets.Include(op => op.basketItems)
                .FirstOrDefault(op => op.ID == id);//. here i used BasketId
            if (existingBasket == null)
                return NotFound("Not Exist");
            var BasketDTO = new BasketDTO
            {
                BasketID = existingBasket.ID,
                UserID = existingBasket.UserID,
                Status = existingBasket.Status,
                items = existingBasket.basketItems.Select(op => new BasketItemDTO
                {
                    ProductID = op.ProductID,
                    Quantity = op.Quantity,
                }).ToList()
            };
            return Ok(BasketDTO);
        }

        [HttpPost("Basket")]
        [Authorize("Customer")]
        public async Task<IActionResult> CreateBasket(BasketItemDTO basketItemDTO)
        {
            var userid = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value);
            var ExistingBasket = DbContext.Baskets.Include(op => op.basketItems)
                .FirstOrDefault(op => op.UserID == userid);
            if (ExistingBasket is not null)
                return BadRequest("Data already exist");
            var basket = new Basket
            {
                UserID = ExistingBasket.UserID,
                basketItems = new List<BasketItems>()
            };
            await DbContext.Baskets.AddAsync(basket);
            await DbContext.SaveChangesAsync();

            var ExistingItems = basket.basketItems.FirstOrDefault(op => op.ProductID == basketItemDTO.ProductID);
            if (ExistingItems != null) //. here will Update the Attributes of BasketItemsDTO
            {
                ExistingItems.Quantity += basketItemDTO.Quantity;
            }
            else
            {
                var newItems = new BasketItems
                {
                    ProductID = basketItemDTO.ProductID,
                    Quantity = basketItemDTO.Quantity,
                    BasketItemsID = basket.ID
                };
                basket.basketItems.Add(newItems);
            }
            await DbContext.SaveChangesAsync();
            return Ok("Done!!");
        }

        [HttpPut("Update/{id}")]
        [Authorize(Roles = "Customer")]
        public async Task<IActionResult> UpdateByID(int id, BasketItemDTO basketItemDTO)
        {
            var existingBasket = DbContext.BasketItems.FirstOrDefault(op => op.BasketItemsID == id);
            if (existingBasket is null)
                return NotFound("Basket not exist");
            existingBasket.ProductID = basketItemDTO.ProductID;
            existingBasket.Quantity = basketItemDTO.Quantity;

            DbContext.BasketItems.Update(existingBasket);
            await DbContext.SaveChangesAsync();
            return Ok();
        }

        [HttpPut("api/{id}")]
        [Authorize(Roles = "Customer")]
        public async Task<IActionResult> UpdateUserId(int id, BasketDTO basketDTO)
        {
            int userIdClaim = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value);
            if (userIdClaim != id)
                return Unauthorized("you are not allowed to access this Basket");
            var existingBasket = await DbContext.Baskets.Include(op => op.basketItems)
                .FirstOrDefaultAsync(op => op.UserID == id);//. will enter Old UserId to access to the Basket
            if (existingBasket is null)
                return NotFound("Basket is not exist");
            existingBasket.UserID = basketDTO.UserID;
            existingBasket.Status = basketDTO.Status;

            DbContext.Baskets.Update(existingBasket);
            await DbContext.SaveChangesAsync();
            return Ok("Updated Successfully");
        }

        [HttpDelete("Delete/{ProductID}")]
        [Authorize(Roles = "Customer")]
        public async Task<IActionResult> DeleteById([FromRoute]int ProductID)
        {
            var existingBasket = await DbContext.BasketItems.FirstOrDefaultAsync(op => op.ProductID == ProductID);
            if (existingBasket == null)
                return NotFound("Not exist");
            DbContext.BasketItems.Remove(existingBasket);
            await DbContext.SaveChangesAsync();
            return Ok("Product Removed Successfully");
        }

        [HttpDelete("Delete/Basket")]
        [Authorize(Roles = "Customer")]
        public async Task<IActionResult> DeleteAllProducts()
        {
            var existingBaskets = await DbContext.Baskets.ToListAsync();

            if (!existingBaskets.Any())
                return NotFound("No baskets found");

            DbContext.Baskets.RemoveRange(existingBaskets);
            await DbContext.SaveChangesAsync();

            return NoContent();//. best case to use
        }


    }
    [ApiController]
    [Authorize]
    [Route("api/[Controller]")]
    public class OrderAPIs : ControllerBase
    {
        private readonly ILogger<OrderAPIs> Logger;

        public OrderAPIs(ILogger<OrderAPIs> logger , AppDbContext dbContext)
        {
            Logger = logger;
            DbContext = dbContext;
        }

        public AppDbContext DbContext { get; }

        [HttpGet("Order/{id}")]
        [Authorize(Roles = "Admin,Customer")]
        public async Task<IActionResult> GetOrderByID([FromRoute] int id)
        {
            var existingOrder = await DbContext.orders.Include(op => op.OrderItems).FirstOrDefaultAsync(op => op.OrderID == id);
            if (existingOrder == null)
                return NotFound("This Order not exist");
            var order = new OrderDTO
            {
                OrderDate = existingOrder.OrderDate,
                Status = existingOrder.Status,
                TotalAmount = existingOrder.TotalAmount,
                OrderID = existingOrder.OrderID,
                OrderItems = existingOrder.OrderItems.Select(op => new OrderItems
                {
                    ProductID = op.ProductID,
                    Quantity = op.Quantity
                }).ToList()
            };
            return Ok(order);
        }

        [HttpGet("Orders")]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult<IEnumerable<Order>>> GetOrders()
        {
            var existingOrders = await DbContext.orders.ToListAsync();
            if (existingOrders == null)
                return Unauthorized("Empty!!");
            return Ok(existingOrders);
        }

        [HttpPost("Orders")]
        [Authorize(Roles = "Customer")]
        public async Task<ActionResult<int>> CreateNewOrder(OrderDTO orderDTO)
        {   
            var order = new Order
            {
                OrderDate = orderDTO.OrderDate,
                Status = orderDTO.Status,
                TotalAmount = orderDTO.TotalAmount,
                OrderItems = orderDTO.OrderItems.Select(op => new OrderItems
                {
                    ProductID = op.ProductID,
                    Quantity = op.Quantity,
                    Price = op.Price
                }).ToList()
            };
            await DbContext.AddAsync(order);
            await DbContext.SaveChangesAsync();
            return Ok(order.OrderID);
        }

        [HttpPut("Update/{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> UpdateById([FromRoute] int id, [FromBody] OrderDTO orderDTO)
        {
            var existingOrder = await DbContext.orders.Include(op => op.OrderItems)
                .FirstOrDefaultAsync(op => op.OrderID == id);
            if (existingOrder == null)
                return BadRequest("Not exist to update");
            existingOrder.OrderDate = orderDTO.OrderDate;
            existingOrder.OrderID = orderDTO.OrderID;
            existingOrder.Status = orderDTO.Status;
            foreach (var items in orderDTO.OrderItems)
            {
                var existingOrderItems = await DbContext.OrderItems.FirstOrDefaultAsync(op => op.ProductID == items.ProductID);
                if (existingOrder != null)
                {
                    existingOrderItems.ProductID = items.ProductID;
                    existingOrderItems.Quantity = items.Quantity;
                    existingOrderItems.Price = items.Price;
                    DbContext.OrderItems.Update(existingOrderItems);
                    await DbContext.SaveChangesAsync();
                    return Ok("Updated Order Successfully");
                }
                else
                {
                    await DbContext.OrderItems.AddAsync(new OrderItems
                    {
                        ProductID = items.ProductID,
                        Quantity = items.Quantity,
                        Price = items.Price
                    });
                }

            }
            await DbContext.SaveChangesAsync();
            return Ok("Updated Order Successfully");
        }

        [HttpDelete("Delete/{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteOrderByID([FromRoute] int id)
        {
            var existingOrder = await DbContext.orders.Include(op => op.OrderItems)
                .FirstOrDefaultAsync(op => op.OrderID == id);
            if (existingOrder == null)
                return NotFound($"Order with ID : `{id}` is not exist");
            //.here you deleted all the factors that have consideration on OrderItems table
            DbContext.OrderItems.RemoveRange(existingOrder.OrderItems);
            //. here you deleted the Order using the id to bring this Order 
            DbContext.orders.Remove(existingOrder);
            await DbContext.SaveChangesAsync();
            return Ok("Order Removed Successfully");
        }
    } 
}
