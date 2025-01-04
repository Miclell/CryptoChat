using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace PolykCrypto.Rsa;

public static class Rsa
{
    public static BigInteger Encrypt(BigInteger message, RsaKey publicKey) =>
        BigInteger.ModPow(message, publicKey.Exponent, publicKey.Modulus);

    public static BigInteger Decrypt(BigInteger cipher, RsaKey privateKey) =>
        BigInteger.ModPow(cipher, privateKey.Exponent, privateKey.Modulus);

    public static (RsaKey publicKey, RsaKey privateKey) GenerateKeys(int length)
    {
        while (true)
        {
            try
            {
                var p = CryptoHelper.GeneratePrime(length / 2);
                var q = CryptoHelper.GeneratePrime(length / 2);

                var n = p * q;
                var phi = (p - 1) * (q - 1);

                // Генерим e: 1 < e < n; НОД(e, n) = 1 
                var e = GenerateE(phi);
        
                // Находим закрытую exp(d) d * e = 1 % phi (модульная инверсия)
                var d = CryptoHelper.ModInverse(e, phi);
        
                var publicKey = new RsaKey(e, n);
                var privateKey = new RsaKey(d, n);

                return (publicKey, privateKey);
            }
            catch (ArithmeticException)
            {
                continue;
            }
        }
    }
    
    public static BigInteger SignData(byte[] data, RsaKey privateKey)
    {
        var hash = SHA256.HashData(data); // Вычисляем хеш данных
        var hashValue = new BigInteger(hash);

        // Подписываем хеш с помощью закрытого ключа
        return BigInteger.ModPow(hashValue, privateKey.Exponent, privateKey.Modulus);
    }

    public static bool VerifySignature(byte[] data, BigInteger signature, RsaKey publicKey)
    {
        var hash = SHA256.HashData(data);
        var hashValue = new BigInteger(hash);

        // Расшифровываем подпись с помощью открытого ключа
        var decryptedHash = BigInteger.ModPow(signature, publicKey.Exponent, publicKey.Modulus);

        // Сравниваем расшифрованный хеш с исходным хешем
        return hashValue == decryptedHash;
    }

    private static BigInteger GenerateE(BigInteger phi)
    {
        // Тупой перебор случаных значений, пока они не станут попарно простыми
        BigInteger e;
        do
        {
            var bytes = new byte[phi.ToByteArray().Length];
            RandomNumberGenerator.Create().GetBytes(bytes);
        
            e = BigInteger.Abs(new BigInteger(bytes)) % (phi - 2) + 2;
        } while (BigInteger.GreatestCommonDivisor(e, phi) != 1);

        return e;
    }
}