using System;
using System.Diagnostics;
using System.Numerics;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using PolykCrypto.Aes;
using PolykCrypto.DiffieHellman;
using PolykCrypto.Rsa;

namespace CryptoChat
{
    public static class Menu
    {
        private static (RsaKey publicKey, RsaKey privateKey) _rsaKeys;
        private static BigInteger _sharedSecret;
        private static AesKey _aesKey = null!;
        private static readonly List<(char Sender, string Encrypted, string Plain, string Signature)> Messages = new();
        private static bool _showEncrypted = false;
        private static int _totalMessages = 0;

        public static void Start()
        {
            while (true)
            {
                var command = Console.ReadLine();
                switch (command)
                {
                    case not null when command.StartsWith("/C"):
                        _showEncrypted = !_showEncrypted;
                        DisplayChat();
                        break;
                    
                    case not null when command.StartsWith("/Init"):
                        InitializeChat();
                        break;

                    case not null when command.StartsWith("/A.Send"):
                        SendMessage('A', command[8..]);
                        break;

                    case not null when command.StartsWith("/B.Send"):
                        SendMessage('B', command[8..]);
                        break;

                    case not null when command.StartsWith("/Exit"):
                        return;
                }
            }
        }

        private static void InitializeChat()
        {
            Console.WriteLine("Инициализация...");

            _rsaKeys = Rsa.GenerateKeys(4096);
            Console.WriteLine($"Публичный - {_rsaKeys.publicKey}\nПриватный - {_rsaKeys.privateKey}");

            var bits = 4096;
            var parameters = DiffieHellman.GenerateParameters(bits);
            Console.WriteLine($"Вычислено общее простое число - {parameters.p.ToString("X")}\nПервообразный корень - {parameters.q}");
            
            var secretA = DiffieHellman.GeneratePrivateKey(bits);
            var secretB = DiffieHellman.GeneratePrivateKey(bits);
            Console.WriteLine($"A сгенерировал секретный ключ - {secretA.ToString("X")}\nB сгенерировал секретный ключ - {secretB.ToString("X")}");
            
            
            var publicA = DiffieHellman.CalculatePublicKey(parameters.q, secretA, parameters.p);
            var publicB = DiffieHellman.CalculatePublicKey(parameters.q, secretB, parameters.p);
            Console.WriteLine($"A сгенерировал публичный ключ - {publicA.ToString("X")}\nB сгенерировал публичный ключ - {publicB.ToString("X")}");

            Console.WriteLine("Обмен ключами...");
            var sharedA = DiffieHellman.CalculateSharedSecret(publicB, secretA, parameters.p);
            var sharedB = DiffieHellman.CalculateSharedSecret(publicA, secretB, parameters.p);

            if (sharedA == sharedB)
            {
                _sharedSecret = sharedA;
                Console.WriteLine($"Получен общий секрет - {sharedA.ToString("X")}\nПолученные секреты равны");
                _aesKey = AesKey.From4096OneKeyBigInteger(_sharedSecret);
            }
            else
            {
                Console.WriteLine("Ошибка генерации общего ключа");
                return;
            }

            Console.WriteLine("Инициализация завершена");
            DisplayHeader();

            Console.ReadLine();
            Console.Clear();
            DisplayHeader();
        }

        private static void SendMessage(char sender, string message)
        {
            if (string.IsNullOrWhiteSpace(message))
            {
                Console.WriteLine("Сообщение не может быть пустым");
                return;
            }

            var plainMessage = message.Trim();
            var aesMessage = AesMessage.FromPlainText(plainMessage);
            aesMessage = aesMessage.Encrypt(_aesKey);

            var encryptedText = aesMessage.ToHexString();
            var messageHash = SHA256.HashData(Encoding.UTF8.GetBytes(plainMessage));

            var signature = Rsa.SignData(messageHash, _rsaKeys.privateKey);
            var verifySign = Rsa.VerifySignature(messageHash, signature, _rsaKeys.publicKey);

            Messages.Add((sender, encryptedText, plainMessage, signature.ToString("X") + " " + verifySign));
            _totalMessages++;

            DisplayHeader();
            DisplayChat();
        }

        private static void DisplayHeader()
        {
            var rsaPubKeyPreview = $"{_rsaKeys.publicKey.ToString()[..5]}...{_rsaKeys.publicKey.ToString()[^5..]}";
            var rsaPrvKeyPreview = $"{_rsaKeys.privateKey.ToString()[..5]}...{_rsaKeys.privateKey.ToString()[^5..]}";
            var sharedKeyPreview = $"{_sharedSecret.ToString()[..5]}...{_sharedSecret.ToString()[^5..]}";

            Console.WriteLine($"| RsaPubKey {rsaPubKeyPreview} | RsaPrvKey {rsaPrvKeyPreview} | Secret {sharedKeyPreview} | Total messages {_totalMessages} |");
        }

        private static void DisplayChat()
        {
            Console.Clear();
            DisplayHeader();

            foreach (var message in Messages)
            {
                Console.WriteLine(_showEncrypted
                    ? $"{message.Sender} - {message.Encrypted} | Подпись: {message.Signature}"
                    : $"{message.Sender} - {message.Plain}");
            }
        }
    }
}
