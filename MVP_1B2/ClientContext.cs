using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using MVP_1B2.Models;
using MVP_1B2.Services;
using System.Globalization;


namespace MVP_1B2
{
    public class ClientContext : IdentityDbContext<ApplicationUser>
    {
        public DbSet<Person> Persons { get; set; }
        public DbSet<Client> Clients { get; set; }
        public DbSet<Employee> Employees { get; set; }
        public DbSet<Service> Services { get; set; }
        public DbSet<ClientService> ClientServices { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }

        private readonly AesGcmEncryptionService _encryption;

        public ClientContext(
            DbContextOptions<ClientContext> options,
            AesGcmEncryptionService encryption)
            : base(options)
        {
            _encryption = encryption;
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            var encryptedStringConverter =
                new ValueConverter<string, string>(
                    value => _encryption.IsEncrypted(value)
                        ? value
                        : _encryption.EncryptString(value),

                    value => _encryption.IsEncrypted(value)
                        ? _encryption.DecryptString(value)
                        : value);

            var encryptedDecimalConverter =
              new ValueConverter<decimal, string>(
                  value => _encryption.EncryptString(
                      value.ToString(CultureInfo.InvariantCulture)),

                  value => _encryption.DecryptDecimal(value));

            var encryptedDateTimeConverter =
               new ValueConverter<DateTime, string>(
                   value => _encryption.EncryptString(
                       value.ToUniversalTime().ToString(
                           "O",
                           CultureInfo.InvariantCulture)),

                   value => _encryption.DecryptDateTime(value));

            var encryptedPhotoConverter =
                new ValueConverter<byte[]?, string?>(
                    value => value == null
                        ? null
                        : Convert.ToBase64String(
                            _encryption.EncryptBytes(value)),

                    value => value == null
                        ? null
                        : _encryption.DecryptBytes(
                            Convert.FromBase64String(value)));

            // -------------------------------
            // Encrypted sensitive information
            // -------------------------------

            modelBuilder.Entity<Person>()
                .Property(p => p.Name)
                .HasConversion(encryptedStringConverter)
                .HasColumnType("nvarchar(max)");

            modelBuilder.Entity<Person>()
                .Property(p => p.Address)
                .HasConversion(encryptedStringConverter)
                .HasColumnType("nvarchar(max)");

            modelBuilder.Entity<Client>()
                .Property(c => c.Balance)
                .HasConversion(encryptedDecimalConverter)
                .HasColumnType("nvarchar(128)");

            modelBuilder.Entity<Client>()
                .Property(c => c.DateOfBirth)
                .HasConversion(encryptedDateTimeConverter)
                .HasColumnType("nvarchar(128)");

            modelBuilder.Entity<Client>()
                .Property(c => c.Photo)
                .HasConversion(encryptedPhotoConverter)
                .HasColumnType("nvarchar(max)");

            modelBuilder.Entity<Person>().ToTable("People");
            modelBuilder.Entity<Client>().ToTable("Clients");
            modelBuilder.Entity<Employee>().ToTable("Employees");
            modelBuilder.Entity<Service>().ToTable("Services");
            modelBuilder.Entity<ClientService>().ToTable("ClientServices");
            
            // Configure the many-to-many relationship between Client and Service
            modelBuilder.Entity<ClientService>()
                .HasKey(cs => new { cs.ClientID, cs.ServiceID });
            modelBuilder.Entity<ClientService>()
                .HasOne(cs => cs.Client)
                .WithMany(c => c.ClientServices)
                .HasForeignKey(cs => cs.ClientID);
            modelBuilder.Entity<ClientService>()
                .HasOne(cs => cs.Service)
                .WithMany(s => s.ClientServices)
                .HasForeignKey(cs => cs.ServiceID);

            // Configure Employee-Service one-to-many relationship
            modelBuilder.Entity<Employee>()
                .HasOne(e => e.Service)
                .WithMany(s => s.Employees)
                .HasForeignKey(e => e.ServiceID)
                .IsRequired(false);

            // Add constraints to Service
            modelBuilder.Entity<Service>()
                .Property(s => s.Name)
                .IsRequired()
                .HasMaxLength(10);

            modelBuilder.Entity<Service>()
                .Property(s => s.Rate)
                .HasDefaultValue(0)
                .IsRequired();

            // ApplicationUser → Client
            modelBuilder.Entity<ApplicationUser>()
                .HasOne(u => u.Client)
                .WithMany()
                .HasForeignKey(u => u.ClientID)
                .OnDelete(DeleteBehavior.NoAction);

            // ApplicationUser → Employee
            modelBuilder.Entity<ApplicationUser>()
                .HasOne(u => u.Employee)
                .WithMany()
                .HasForeignKey(u => u.EmployeeID)
                .OnDelete(DeleteBehavior.NoAction);

            //Audit log
            modelBuilder.Entity<AuditLog>()
                .Property(a => a.TimestampUtc)
                .HasColumnType("datetime2(7)");

        }
    }
}
