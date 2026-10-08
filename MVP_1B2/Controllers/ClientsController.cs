using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using MVP_1B2;
using MVP_1B2.Models;
using MVP_1B2.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MVP_1B2.Controllers
{
    [Authorize]
    public class ClientsController : Controller
    {
        private readonly ClientContext _context;
        private readonly AuditService _auditService;
        private readonly UserManager<ApplicationUser> _userManager;
        public ClientsController(ClientContext context, UserManager<ApplicationUser> userManager, AuditService auditService)
               
        {
            _context = context;
            _userManager = userManager;
            _auditService = auditService;
        }

        //Profile action
        [Authorize(Roles = "Client")]
        public async Task<IActionResult> MyProfile()
        {
            var user = await _userManager.GetUserAsync(User);

            if (user == null || user.ClientID == null)
            {
                return Forbid();
            }

            var client = await _context.Clients
                .Include(c => c.ClientServices)
                .ThenInclude(cs => cs.Service)
                .FirstOrDefaultAsync(c => c.ID == user.ClientID);

            if (client == null)
            {
                return NotFound();
            }

            return View("Details", client);
        }

        //Query client counts in each citys  

        [Authorize(Roles = "Administrator,Manager,Employee")]
        public async Task<IActionResult> ClientsByCity()
        {
            var cityClientCount = await _context.Clients
                .GroupBy(c => c.Address)
                .Select(g => new
                {
                    City = g.Key,
                    ClientCount = g.Count()
                })
                .OrderBy(result => result.City)
                .ToListAsync();

            return View(cityClientCount);
        }

        //Query Clients without service

        [Authorize(Roles = "Administrator,Manager,Employee")]
        public async Task<IActionResult> ClientsWithoutServices()
        {
            var clientsWithoutServices = await _context.Clients
                .Where(c => !_context.ClientServices.Any(cs => cs.ClientID == c.ID))
                .ToListAsync();

            return View(clientsWithoutServices);
        }


        // GET: Clients1

        [Authorize(Roles = "Administrator,Manager,Employee")]
        public async Task<IActionResult> Index()
        {
            var clients = await _context.Clients
            .Include(c => c.ClientServices)
            .ThenInclude(cs => cs.Service)
            .ToListAsync();
            return View(clients);

            //return View(await _context.Clients.ToListAsync());
        }

        // GET: Clients1/Details/5
        [Authorize(Roles = "Administrator,Manager,Employee")]
        public async Task<IActionResult> Details(Guid? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var client = await _context.Clients
            .Include(c => c.ClientServices)
            .ThenInclude(cs => cs.Service) // Ensure related Service data is included
            .FirstOrDefaultAsync(m => m.ID == id);
            if (client == null)
            {
                return NotFound();
            }
            return View(client);
            //return View(client);
        }



        // GET: Clients1/Create

        [Authorize(Roles = "Administrator,Manager")]
        public IActionResult Create()
        {
            ViewData["Services"] = new MultiSelectList(_context.Services, "ID", "Name");
            return View();
        }

        // POST: Clients1/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Administrator,Manager")]
        public async Task<IActionResult> Create(
           [Bind("Balance,DateOfBirth,Photo,ID,Name,Address,Email,PhoneNumber")] Client client,
           Guid[] selectedServices,
           IFormFile? PhotoFile)
        {
            // Photo upload
            if (PhotoFile != null && PhotoFile.Length > 0)
            {
                using (var memoryStream = new MemoryStream())
                {
                    await PhotoFile.CopyToAsync(memoryStream);
                    client.Photo = memoryStream.ToArray();
                }
            }

            if (!ModelState.IsValid)
            {
                ViewData["Services"] =
                    new MultiSelectList(_context.Services, "ID", "Name", selectedServices);

                return View(client);
            }

            // Make sure the Client has an ID
            client.ID = Guid.NewGuid();

            // Make sure the email is available
            if (string.IsNullOrWhiteSpace(client.Email))
            {
                ModelState.AddModelError("Email",
                    "A client email address is required to create an account.");

                ViewData["Services"] =
                    new MultiSelectList(_context.Services, "ID", "Name", selectedServices);

                return View(client);
            }

            // Check whether email is already used by an Identity account
            var existingUser = await _userManager.FindByEmailAsync(client.Email);

            if (existingUser != null)
            {
                ModelState.AddModelError("Email",
                    "This email address is already associated with an account.");

                ViewData["Services"] =
                    new MultiSelectList(_context.Services, "ID", "Name", selectedServices);

                return View(client);
            }

            // Create Client
            _context.Clients.Add(client);

            // Add selected services
            if (selectedServices != null)
            {
                foreach (var serviceId in selectedServices)
                {
                    _context.ClientServices.Add(new ClientService
                    {
                        ClientID = client.ID,
                        ServiceID = serviceId
                    });
                }
            }

            // Create Identity account
            var temporaryPassword = "TempPassword123!";

            var user = new ApplicationUser
            {
                UserName = client.Email,
                Email = client.Email,
                EmailConfirmed = false,
                ClientID = client.ID,
                PhoneNumber = client.PhoneNumber
            };

            var result = await _userManager.CreateAsync(
                user,
                temporaryPassword);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }

                ViewData["Services"] =
                    new MultiSelectList(_context.Services, "ID", "Name", selectedServices);

                return View(client);
            }

            // Assign Client role
            var roleResult = await _userManager.AddToRoleAsync(
                user,
                "Client");

            if (!roleResult.Succeeded)
            {
                foreach (var error in roleResult.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }

                // Remove the Identity account if role assignment failed
                await _userManager.DeleteAsync(user);

                ViewData["Services"] =
                    new MultiSelectList(_context.Services, "ID", "Name", selectedServices);

                return View(client);
            }

            // Save Client + ClientServices
            await _context.SaveChangesAsync();

            var userId =
                User.Identity?.Name ?? "Unknown";

                        await _auditService.LogAsync(
                            userId,
                            "Create",
                            "Client",
                            client.ID.ToString(),
                            "Created client");

            TempData["Success"] =
                $"Client account created successfully. Temporary password: {temporaryPassword}";

            return RedirectToAction(nameof(Index));
        }

        // GET: Clients1/Edit/5

        [Authorize(Roles = "Administrator,Manager")]
        public async Task<IActionResult> Edit(Guid? id)
        {
            if (id == null)
            {
                return NotFound();
            }
            //addded 
            var client = _context.Clients
              .Include(c => c.ClientServices)
              .FirstOrDefault(c => c.ID == id);


            if (client == null)
            {
                return NotFound();
            }
            
           
            var selectedServices = client.ClientServices.Select(cs => cs.ServiceID).ToList();
            ViewData["Services"] = new MultiSelectList(_context.Services, "ID", "Name", client.ClientServices.Select(cs => cs.ServiceID));

            return View(client);
        }

        // POST: Clients1/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        // POST: Clients1/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Administrator,Manager")]
        public async Task<IActionResult> Edit(Guid id, [Bind("Balance,DateOfBirth,Photo,ID,Name,Address,Email,PhoneNumber")] Client client, Guid[] selectedServices, bool DeleteAllServices, IFormFile? PhotoFile)
        {
            if (id != client.ID)
            {
                return NotFound();
            }

            // Find the existing client from the context
            var existingClient = await _context.Clients.Include(c => c.ClientServices).FirstOrDefaultAsync(c => c.ID == id);

            if (existingClient == null)
            {
                return NotFound();
            }

            // If there's a new photo, update it
            if (PhotoFile != null && PhotoFile.Length > 0)
            {
                using (var memoryStream = new MemoryStream())
                {
                    await PhotoFile.CopyToAsync(memoryStream);
                    existingClient.Photo = memoryStream.ToArray(); // Update the photo
                }
            }

            // If no new photo, keep the old one
            else
            {
                existingClient.Photo = existingClient.Photo; // No changes to photo
            }

            // Update other fields from the posted client object
            existingClient.Balance = client.Balance;
            existingClient.DateOfBirth = client.DateOfBirth;
            existingClient.Name = client.Name;
            existingClient.Address = client.Address;
            existingClient.Email = client.Email;
            existingClient.PhoneNumber = client.PhoneNumber;


            // Handle services - remove old and add new services if necessary
            if (DeleteAllServices)
            {
                // Remove all current services
                _context.ClientServices.RemoveRange(existingClient.ClientServices);
            }

            if (selectedServices != null)
            {
                // Add new selected services
                foreach (var serviceId in selectedServices)
                {
                    var existingClientService = existingClient.ClientServices
                        .FirstOrDefault(cs => cs.ServiceID == serviceId);

                    if (existingClientService == null) // Only add if the service is not already assigned
                    {
                        _context.ClientServices.Add(new ClientService
                        {
                            ClientID = existingClient.ID,
                            ServiceID = serviceId
                        });
                    }
                }
            }

            // Mark the entity as modified and save changes
            _context.Clients.Update(existingClient);
            await _context.SaveChangesAsync();
            var userId =
                User.Identity?.Name ?? "Unknown";

                        await _auditService.LogAsync(
                            userId,
                            "Edit",
                            "Client",
                            client.ID.ToString(),
                            "Edited client");

            return RedirectToAction(nameof(Index));
        }



        // GET: Clients1/Delete/5
        [Authorize(Roles = "Administrator,Manager")]
        public async Task<IActionResult> Delete(Guid? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            //var client = await _context.Clients
            //    .FirstOrDefaultAsync(m => m.ID == id);

            var client = await _context.Clients
            .Include(c => c.ClientServices) // Load the related ClientServices
            .ThenInclude(cs => cs.Service)  // Load the actual Service entity
            .FirstOrDefaultAsync(m => m.ID == id);

            if (client == null)
            {
                return NotFound();
            }

            return View(client);
        }

        // POST: Clients1/Delete/5
        // POST: Clients1/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Administrator,Manager")]
        public async Task<IActionResult> DeleteConfirmed(Guid id)
        {
            var client = await _context.Clients.FindAsync(id);

            if (client == null)
            {
                return NotFound();
            }

            // Find the ASP.NET Identity account associated with this client
            var user = await _userManager.Users
                .FirstOrDefaultAsync(u => u.ClientID == client.ID);

            // Delete the Identity account first
            if (user != null)
            {
                var result = await _userManager.DeleteAsync(user);

                if (!result.Succeeded)
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("", error.Description);
                    }

                    return View("Delete", client);
                }
            }

            // Then delete the Client
            _context.Clients.Remove(client);

            await _context.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateClientAccount(Guid clientId)
        {
            var client = await _context.Clients
                .FirstOrDefaultAsync(c => c.ID == clientId);

            if (client == null)
            {
                return NotFound();
            }

            if (string.IsNullOrWhiteSpace(client.Email))
            {
                TempData["Error"] =
                    "This client does not have an email address.";

                return RedirectToAction(
                    "Details",
                    "Clients",
                    new { id = clientId });
            }

            // Check whether this client already has an account
            var existingUser = await _userManager.Users
                .FirstOrDefaultAsync(u => u.ClientID == clientId);

            if (existingUser != null)
            {
                TempData["Error"] =
                    "This client already has an account.";

                return RedirectToAction(
                    "Details",
                    "Clients",
                    new { id = clientId });
            }

            // Check whether the email is already used
            var existingEmailUser =
                await _userManager.FindByEmailAsync(client.Email);

            if (existingEmailUser != null)
            {
                TempData["Error"] =
                    "This email address is already associated with an account.";

                return RedirectToAction(
                    "Details",
                    "Clients",
                    new { id = clientId });
            }

            var temporaryPassword = "TempPassword123!";

            var user = new ApplicationUser
            {
                UserName = client.Email,
                Email = client.Email,
                EmailConfirmed = false,
                ClientID = client.ID,
                PhoneNumber = client.PhoneNumber
            };

            var result = await _userManager.CreateAsync(
                user,
                temporaryPassword);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }

                return RedirectToAction(
                    "Details",
                    "Clients",
                    new { id = clientId });
            }

            var roleResult = await _userManager.AddToRoleAsync(
                user,
                "Client");

            if (!roleResult.Succeeded)
            {
                foreach (var error in roleResult.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }

                return RedirectToAction(
                    "Details",
                    "Clients",
                    new { id = clientId });
            }

            TempData["Success"] =
                $"Client account created. Temporary password: {temporaryPassword}";

            return RedirectToAction(
                "Details",
                "Clients",
                new { id = clientId });
        }
        private bool ClientExists(Guid id)
        {
            return _context.Clients.Any(e => e.ID == id);
        }

        [Authorize(Roles = "Administrator,Manager,Employee")]
        public async Task<IActionResult> VerifyAudit(int id)
        {
            var auditLog = await _context.AuditLogs
                .FirstOrDefaultAsync(a => a.Id == id);

            if (auditLog == null)
                return NotFound();

            bool isValid = _auditService.Verify(auditLog);

            ViewBag.IsValid = isValid;
            ViewBag.AuditLog = auditLog;

            return View();
        }
    }
}
