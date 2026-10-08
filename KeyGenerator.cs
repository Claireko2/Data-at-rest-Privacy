using System.Security.Cryptography;

using RSA rsa = RSA.Create(3072);

string privateKey =
    Convert.ToBase64String(
        rsa.ExportPkcs8PrivateKey());

string publicKey =
    Convert.ToBase64String(
        rsa.ExportSubjectPublicKeyInfo());

Console.WriteLine("PRIVATE KEY:");
Console.WriteLine(privateKey);

Console.WriteLine();
Console.WriteLine("PUBLIC KEY:");
Console.WriteLine(publicKey);
