# MVP_1B2 - Secure ASP.NET Core MVC Application

A secure ASP.NET Core MVC web application developed for the **BCIT Database Security** course. The project demonstrates practical implementation of database security, data privacy, authentication, authorization, encryption, digital signatures, custom stream-cipher design, software licensing, HTTPS, mutual TLS, IP filtering, and multi-factor authentication.

---

## 1. Project Overview

`MVP_1B2` is an ASP.NET Core MVC application for managing clients, employees, services, and related information.

The project was enhanced with multiple security mechanisms to protect sensitive information and demonstrate different security principles.

### Main security objectives

* Protect sensitive data stored in the database.
* Protect sensitive files stored in application folders.
* Provide integrity and authenticity through digital signatures.
* Implement non-repudiation for important application actions.
* Implement software license verification.
* Prevent unauthorized modification of license information.
* Demonstrate HTTPS and mutual TLS.
* Restrict access using IP filtering.
* Implement authentication, authorization, and multi-factor authentication.
* Reduce risks associated with reverse engineering and software piracy.

---

# 2. Technology Stack

| Component               | Technology                         |
| ----------------------- | ---------------------------------- |
| Framework               | ASP.NET Core                       |
| Language                | C#                                 |
| Target Framework        | .NET 9                             |
| Web Framework           | ASP.NET Core MVC                   |
| ORM                     | Entity Framework Core              |
| Database                | Microsoft SQL Server               |
| Authentication          | ASP.NET Core Identity              |
| External Authentication | Microsoft Entra ID / Azure AD      |
| MFA                     | Twilio SMS                         |
| Database Encryption     | AES-GCM                            |
| Digital Signatures      | RSA + SHA-256                      |
| Custom Stream Cipher    | C# custom ARX-based implementation |
| HTTPS                   | TLS                                |
| Mutual TLS              | Client certificates                |
| IP Protection           | Custom IP filtering middleware     |
| Obfuscation             | Obfuscar                           |
| Licensing               | RSA-signed license                 |
| Development Environment | Visual Studio / .NET CLI           |

---

# 3. Project Structure

The solution contains the main MVC application and a separate license issuer application.

```text
MVP_1B2/
│
├── MVP_1B2/
│   ├── Controllers/
│   ├── Data/
│   ├── Middleware/
│   ├── Models/
│   ├── Services/
│   ├── Views/
│   ├── App_Data/
│   │   └── license.json
│   ├── wwwroot/
│   ├── Program.cs
│   └── appsettings.json
│
├── MVP_1B2.LicenseIssuer/
│   ├── Program.cs
│   └── MVP_1B2.LicenseIssuer.csproj
│
└── README.md
```

The `MVP_1B2.LicenseIssuer` project is intentionally separated from the MVC application.

The license issuer holds the private signing key and is responsible for creating signed licenses. The MVC application only needs the corresponding public key to verify licenses.

---

# 4. Security Architecture

The application uses multiple layers of security rather than relying on a single mechanism.

```text
                         ┌─────────────────────┐
                         │   ASP.NET MVC App   │
                         └──────────┬──────────┘
                                    │
             ┌──────────────────────┼──────────────────────┐
             │                      │                      │
             ▼                      ▼                      ▼
       Authentication         Authorization          IP Filtering
       ASP.NET Identity       Roles / Policies        Middleware
             │
             ▼
        MFA / SSO
       Twilio / Entra ID

             ┌────────────────────────────────────────────┐
             │              Data Protection               │
             ├────────────────────────────────────────────┤
             │ AES-GCM for sensitive database fields      │
             │ Custom stream cipher for sensitive files   │
             └────────────────────────────────────────────┘

             ┌────────────────────────────────────────────┐
             │           Integrity / Authenticity         │
             ├────────────────────────────────────────────┤
             │ RSA digital signatures                     │
             │ Audit log non-repudiation                  │
             │ RSA-signed software license                │
             └────────────────────────────────────────────┘

             ┌────────────────────────────────────────────┐
             │             Network Security               │
             ├────────────────────────────────────────────┤
             │ HTTPS / TLS                                │
             │ Mutual TLS / Client Certificates           │
             └────────────────────────────────────────────┘
```

---

# 5. Authentication and Authorization

The application uses **ASP.NET Core Identity** for user authentication.

Password security is handled by ASP.NET Core Identity rather than storing passwords directly.

Password requirements include:

* Minimum length of 12 characters.
* At least one digit.
* At least one lowercase character.
* At least one uppercase character.
* At least one non-alphanumeric character.
* Account lockout after repeated failed attempts.

Example configuration:

```csharp
options.Password.RequireDigit = true;
options.Password.RequireLowercase = true;
options.Password.RequireUppercase = true;
options.Password.RequireNonAlphanumeric = true;
options.Password.RequiredLength = 12;

options.Lockout.MaxFailedAccessAttempts = 5;

options.Lockout.DefaultLockoutTimeSpan =
    TimeSpan.FromMinutes(15);
```

## Roles

The application uses role-based authorization.

Available roles include:

* Administrator
* Manager
* Employee
* Client

Access to controllers and operations is restricted according to the user's role.

For example, administrative operations such as managing employees and assigning certain roles are restricted to authorized users.

---

# 6. Microsoft Entra ID / Azure AD SSO

The application also supports external authentication through Microsoft Entra ID.

The OpenID Connect integration allows authorized users to authenticate through an organizational Microsoft account.

This provides an additional authentication mechanism while allowing the application to use ASP.NET Core Identity for local application authorization.

---

# 7. Two-Factor Authentication

The application includes a Twilio-based SMS two-factor authentication mechanism.

The application uses a custom token provider and `ITwoFactorService` / `TwilioTwoFactorService` to support SMS-based verification.

The purpose of MFA is to add another authentication factor beyond the user's password.

Sensitive Twilio credentials should be stored in configuration secrets or environment variables and must not be committed to GitHub.

---

# 8. Data Privacy and Database Encryption

Sensitive data stored in the database is encrypted using **AES-GCM**.

The encryption service is implemented in:

```text
Services/AesGcmEncryptionService.cs
```

AES-GCM provides both:

* Confidentiality
* Authentication/integrity protection

A 256-bit AES key is loaded from application configuration.

For each encryption operation, a new random 96-bit nonce is generated.

```text
AES Key
   +
Random Nonce
   +
Plaintext
      │
      ▼
   AES-GCM
      │
      ▼
Ciphertext + Authentication Tag
```

The nonce and authentication tag are stored together with the encrypted data.

---

# 9. Sensitive Database Fields

The following fields are protected using Entity Framework Core value converters:

### Person

* `Name`
* `Address`

### Client

* `Balance`
* `DateOfBirth`
* `Photo`

For example:

```csharp
modelBuilder.Entity<Person>()
    .Property(p => p.Name)
    .HasConversion(encryptedStringConverter);
```

The application automatically encrypts values when they are written to the database and decrypts them when they are loaded.

This allows application code to continue working with normal C# types while sensitive values remain encrypted at rest.

---

# 10. Why Some Fields Are Not Encrypted

Not every field should be encrypted.

Primary keys and foreign keys should generally remain usable for database relationships.

ASP.NET Identity also manages authentication-related information separately.

Passwords are not encrypted with AES. Passwords are handled by ASP.NET Core Identity using password hashing.

Email and phone-number fields are also treated carefully because they may participate in identity/account functionality.

---

# 11. AES-GCM Data Format

The custom encryption service produces encrypted byte data containing:

```text
12-byte nonce
      +
16-byte authentication tag
      +
ciphertext
```

Conceptually:

```text
┌────────────┬──────────────┬─────────────────────┐
│   Nonce    │     Tag      │     Ciphertext      │
│  12 bytes  │   16 bytes   │ variable length     │
└────────────┴──────────────┴─────────────────────┘
```

During decryption, the authentication tag is verified. If the encrypted data has been modified, AES-GCM decryption fails.

---

# 12. Non-Repudiation

The application implements digital signatures for audit records.

The main components are:

```text
Services/NonRepudiationService.cs
Services/AuditService.cs
Models/AuditLog.cs
```

When an important action occurs, an audit record is created containing:

* User ID
* Action
* Entity type
* Entity ID
* Timestamp
* Details
* Digital signature

The canonical audit data is constructed from these fields:

```text
UserId
+
Action
+
EntityType
+
EntityId
+
Timestamp
+
Details
```

The resulting data is digitally signed using an RSA private key and SHA-256.

```text
Audit Data
     │
     ▼
   SHA-256
     │
     ▼
RSA Private Key
     │
     ▼
Digital Signature
```

The signature is stored with the audit record.

---

# 13. Audit Log Verification

When an audit record is verified, the application reconstructs the original canonical data and verifies the stored signature using the RSA public key.

```text
Stored Audit Data
       +
Stored Signature
       +
RSA Public Key
          │
          ▼
     Verification
          │
      ┌───┴───┐
      ▼       ▼
    Valid   Invalid
```

If an attacker modifies an audit record, such as changing:

```text
Details = "Updated client"
```

to:

```text
Details = "Deleted client"
```

the signature verification fails.

This demonstrates the integrity protection provided by digital signatures.

---

# 14. RSA Key Management

The RSA key pair used for non-repudiation is generated separately from the RSA key pair used for software licensing.

The private key must never be committed to the Git repository.

The public key can be distributed with the application because it is used only for verification.

The security model is:

```text
Private Key
     │
     └── kept secret
            │
            ▼
       Create Signature


Public Key
     │
     └── distributed with application
            │
            ▼
       Verify Signature
```

---

# 15. Custom Stream Cipher

The application also implements a custom stream cipher from scratch for sensitive files.

The implementation is located in:

```text
Services/CustomStreamCipherService.cs
```

The implementation does not use a built-in stream cipher such as RC4 or ChaCha20.

Instead, it implements a custom ARX-based construction inspired by concepts used in modern stream ciphers.

ARX means:

* Addition
* Rotation
* XOR

The cipher uses:

* A 256-bit key
* A 96-bit nonce
* A counter
* 64-byte keystream blocks

---

# 16. Custom Stream Cipher Design

The keystream generation uses a 16-word state.

The state contains:

```text
Constants
+
256-bit Key
+
Counter
+
96-bit Nonce
```

The cipher performs multiple rounds of custom quarter-round operations.

A simplified representation is:

```text
Key + Nonce + Counter
          │
          ▼
       State
          │
          ▼
     ARX rounds
          │
          ▼
    Keystream block
          │
          ▼
Plaintext XOR Keystream
          │
          ▼
       Ciphertext
```

The same transformation is used for encryption and decryption because:

```text
Ciphertext XOR Keystream
=
Plaintext
```

---

# 17. XOR-Based Encryption

For each block:

```text
Ciphertext = Plaintext XOR Keystream
```

For decryption:

```text
Plaintext = Ciphertext XOR Keystream
```

The nonce and counter ensure that different blocks produce different keystream material.

A nonce must never be reused with the same key.

---

# 18. Stream Cipher and Large Files

The design is intended for sensitive files such as files stored under the `Assets` directory and its subdirectories.

The stream-cipher approach is suitable for large files because the encryption process can operate incrementally on blocks instead of requiring the entire file to be processed as one large memory object.

The current `Transform()` method demonstrates the core block-by-block transformation.

For production-scale file processing, a `FileStream`-based implementation can process files incrementally.

---

# 19. Important Security Note

The custom stream cipher is an educational implementation created specifically for the assignment.

It is **not intended to replace professionally reviewed cryptographic algorithms in production systems**.

The purpose is to demonstrate understanding of:

* Stream cipher construction
* Keystream generation
* Nonces
* Counters
* XOR encryption
* ARX operations
* Weakness mitigation concepts inspired by stronger stream ciphers

---

# 20. Software Licensing

The application implements RSA-signed software licensing.

The licensing system consists of two components:

```text
MVP_1B2.LicenseIssuer
        +
MVP_1B2 MVC Application
```

The License Issuer creates licenses.

The MVC application verifies licenses.

---

# 21. License Issuer

The separate console application:

```text
MVP_1B2.LicenseIssuer
```

can generate an RSA key pair:

```powershell
dotnet run --project MVP_1B2.LicenseIssuer -- generate-key LicensingKeys
```

This generates:

```text
LicensingKeys/
├── license-private.pem
└── license-public.pem
```

The private key is used to sign licenses.

The public key is used by the MVC application to verify licenses.

The private key must never be deployed with the MVC application.

---

# 22. Creating a License

A license can be issued using:

```powershell
dotnet run --project MVP_1B2.LicenseIssuer -- issue LicensingKeys\license-private.pem MVP_1B2\App_Data\license.json DEMO-VALID-001 DEMO-CORP Trial 2026-10-07T00:00:00Z 2026-12-07T23:59:59Z
```

The license contains information such as:

```text
License ID
Customer ID
License Type
Issued Date
Valid From
Valid Until
```

The payload is digitally signed using the license issuer's RSA private key.

---

# 23. License Verification

The MVC application contains:

```text
Services/LicenseVerificationService.cs
```

At application startup, the service:

1. Loads the license file.
2. Loads the RSA public key.
3. Verifies the digital signature.
4. Checks the license validity period.
5. Stores the resulting license state.
6. Allows or restricts application access based on the result.

The verification is performed at **application startup**, rather than once per user session.

---

# 24. License Validation Logic

There are two main validation checks.

### Signature verification

```text
Is the license authentic?

Was it signed by the authorized license issuer?

Has the signed content been modified?
```

### Date verification

```text
Is the current UTC time between
ValidFromUtc and ValidUntilUtc?
```

The overall result is:

```text
Signature Valid
       AND
Date Valid
       =
License Valid
```

---

# 25. License Tampering Test

A valid license can be tested by manually modifying its contents.

For example:

```text
Original:

ValidUntilUtc = 2026-12-07
```

Change it to:

```text
ValidUntilUtc = 2030-12-07
```

The original signature no longer matches the modified payload.

The application should report:

```text
License signature valid: False
```

This demonstrates that users cannot simply edit the license expiration date without invalidating the digital signature.

To legitimately change the license contents, a new license must be issued using the private signing key.

---

# 26. Expired License Test

An expired license can be generated using the License Issuer with a validity period in the past.

For example:

```powershell
dotnet run --project MVP_1B2.LicenseIssuer -- issue LicensingKeys\license-private.pem MVP_1B2\App_Data\license.json DEMO-EXPIRED-001 DEMO-CORP Trial 2026-01-01T00:00:00Z 2026-02-01T23:59:59Z
```

The expected result is:

```text
License signature valid: True
License date valid: False
Overall license valid: False
```

The signature remains valid because the license itself was legitimately issued, but the license is no longer within its permitted validity period.

---

# 27. License Status Page

The application provides:

```text
/License/Status
```

The status page displays information such as:

* License ID
* Customer
* License type
* Signature status
* Date status
* Valid-from date
* Valid-until date
* Overall license status

This allows users and administrators to understand why a license is invalid.

For example:

```text
License Status

The license has expired.

License ID: DEMO-EXPIRED-001
Customer: DEMO-CORP
License Type: Trial

Signature Valid: True
Date Valid: False
```

If the license has been modified:

```text
License Status

The license signature is invalid.
The license may have been modified.

Signature Valid: False
```

---

# 28. HTTPS and TLS

The application supports HTTPS using ASP.NET Core Kestrel.

HTTPS provides protection against network-level interception by encrypting communication between the client and server.

The application includes HTTPS endpoints configured through Kestrel.

---

# 29. Mutual TLS

The project also demonstrates mutual TLS using client certificates.

Unlike normal HTTPS, where the server authenticates itself to the client, mutual TLS allows both sides to authenticate.

```text
Client
   │
   │ Client Certificate
   ▼
Server
   │
   │ Certificate validation
   ▼
Authenticated connection
```

The application validates the expected client certificate thumbprint.

The demonstration endpoint is:

```text
/certificate-test
```

The endpoint displays certificate information when a valid client certificate is presented.

---

# 30. IP Filtering

The application includes custom IP filtering middleware.

The middleware checks the client's IP address against configured allowed addresses.

This provides an additional network-level access control mechanism.

A test endpoint is available at:

```text
/ip-test
```

If the request is allowed, the application returns the client's detected IP address.

---

# 31. Anti-Reverse-Engineering Measures

The application includes obfuscation using **Obfuscar**.

The purpose is to make reverse engineering more difficult by transforming compiled code so that it is harder to understand while preserving its functionality.

Obfuscation is particularly relevant to protecting application logic related to licensing and other security-sensitive components.

Obfuscation should be treated as an additional security layer rather than a replacement for cryptographic protection.

---

# 32. Configuration and Secrets

Sensitive configuration values should not be stored directly in source code.

Examples include:

```text
AES encryption key
Custom stream cipher key
RSA private keys
Twilio credentials
Azure authentication secrets
Database connection strings
```

Development secrets should be stored using:

* .NET User Secrets
* Environment variables
* Secure deployment configuration

For example:

```powershell
dotnet user-secrets set "Encryption:AesKey" "<BASE64_KEY>"
```

Never commit actual private keys, authentication tokens, or encryption keys to GitHub.

---

# 33. `.gitignore`

The following types of files should be excluded from source control:

```gitignore
LicensingKeys/
*.pem

appsettings.Development.json

.vs/
bin/
obj/
```

Additional secret files should also be excluded as appropriate.

---

# 34. Running the Project

## Prerequisites

Install:

* .NET 9 SDK
* Microsoft SQL Server
* Visual Studio 2022 or later
* ASP.NET Core development tools

Optional security integrations:

* Twilio account for SMS MFA
* Microsoft Entra ID application registration

---

## Clone the repository

```powershell
git clone <repository-url>
cd MVP_1B2
```

---

## Configure the database

Update the development connection string through secure configuration.

Example:

```text
ConnectionStrings:DefaultConnection
```

Do not commit production database credentials.

---

# 35. Generate License Keys

From the solution directory:

```powershell
dotnet run --project MVP_1B2.LicenseIssuer -- generate-key LicensingKeys
```

Keep:

```text
license-private.pem
```

outside the MVC application's deployment environment.

Copy only the public key where the MVC application can access it.

---

# 36. Issue a Development License

Example:

```powershell
dotnet run --project MVP_1B2.LicenseIssuer -- issue LicensingKeys\license-private.pem MVP_1B2\App_Data\license.json DEMO-VALID-001 DEMO-CORP Trial 2026-10-07T00:00:00Z 2026-12-07T23:59:59Z
```

---

# 37. Start the Application

Run the MVC project:

```powershell
dotnet run --project MVP_1B2
```

During startup, the application performs license verification.

A successful verification produces output similar to:

```text
License exists: True
License signature valid: True
License date valid: True
Overall license valid: True
License verified: DEMO-VALID-001
License type: Trial
```

---

# 38. Testing Security Features

The following tests can be used to demonstrate the security mechanisms.

| Test                       | Expected Result                  |
| -------------------------- | -------------------------------- |
| Valid license              | Application operates normally    |
| Expired license            | License date validation fails    |
| Future license             | License date validation fails    |
| Modified license           | RSA signature validation fails   |
| Modified audit record      | Audit signature validation fails |
| Modified encrypted data    | AES-GCM authentication fails     |
| Invalid client certificate | mTLS request rejected            |
| Unauthorized IP            | Request rejected                 |
| Incorrect user role        | Authorization denied             |
| Incorrect MFA code         | Authentication fails             |

---

# 39. Security Design Summary

The project demonstrates several complementary security controls.

### Confidentiality

* AES-GCM database encryption
* Custom stream cipher for sensitive files
* HTTPS/TLS

### Integrity

* AES-GCM authentication tags
* RSA digital signatures
* Signed software licenses
* Audit log signatures

### Authentication

* ASP.NET Core Identity
* Microsoft Entra ID / Azure AD
* SMS-based MFA
* Mutual TLS client certificates

### Authorization

* Role-based authorization
* Authorization policies
* IP filtering

### Software Protection

* RSA-signed licensing
* License expiration
* License tampering detection
* Code obfuscation

---

# 40. Important Limitations

Some components are implemented for educational purposes and should not be considered replacements for mature production security solutions.

### Custom stream cipher

The custom stream cipher demonstrates stream-cipher concepts but has not undergone professional cryptanalysis.

Production systems should use standardized, well-reviewed cryptographic algorithms.

### Client certificate validation

The demonstration currently uses certificate thumbprint validation. A production PKI should use proper certificate-chain validation, certificate revocation checking, and appropriate certificate lifecycle management.

### License verification

The license protects the signed license contents from unauthorized modification. However, a client-side licensing mechanism cannot completely prevent a sufficiently privileged attacker from modifying the application itself.

### Key protection

Private keys must be protected outside the application deployment environment.

---

# 41. Security Principles Demonstrated

This project demonstrates the following security principles:

1. **Defense in depth**
   Multiple independent security mechanisms protect the application.

2. **Least privilege**
   Users receive permissions according to their roles.

3. **Confidentiality**
   Sensitive information is encrypted at rest and in transit.

4. **Integrity**
   Digital signatures and authentication tags detect unauthorized modifications.

5. **Authentication**
   Multiple authentication mechanisms verify user and system identities.

6. **Separation of keys**
   Different cryptographic keys are used for different security purposes.

7. **Fail-closed security**
   Invalid authentication, authorization, certificate, or license conditions should not grant protected access.

8. **Secure key management**
   Private keys and secrets are kept outside source control and should not be distributed unnecessarily.

---

# 42. Academic Context

This project was developed as part of the **BCIT Database Security** coursework.

The implementation focuses on applying theoretical security concepts to a working ASP.NET Core MVC application, including:

* Data privacy
* Symmetric encryption
* Stream ciphers
* Digital signatures
* Non-repudiation
* RSA
* Software licensing
* Authentication
* Authorization
* TLS
* Mutual TLS
* Network access control
* Software protection

The project emphasizes practical implementation and testing of security mechanisms rather than relying solely on theoretical descriptions.
