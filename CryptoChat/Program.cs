using System.Collections.Concurrent;
using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using PolykCrypto;
using PolykCrypto.Aes;
using PolykCrypto.DiffieHellman;
using PolykCrypto.Rsa;
using Aes = System.Security.Cryptography.Aes;

namespace CryptoChat;

public static class Program
{
    public static void Main()
    {
        Console.WriteLine("Мега крипто чат");

        Menu.Start();
    }
}