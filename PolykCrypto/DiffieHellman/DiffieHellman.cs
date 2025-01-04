using System.Numerics;
using System.Security.Cryptography;

namespace PolykCrypto.DiffieHellman;

public static class DiffieHellman
{
    public static (BigInteger p, BigInteger q) GenerateParameters(int bits)
    {
        var p = CryptoHelper.GeneratePrimePlusOne(bits, out var n);
        var q = CryptoHelper.FindPrimitiveRoot(p, n);
        
        return (p, q);
    }

    public static BigInteger GeneratePrivateKey(int bits)
    {
        var bytes = new byte[bits / 8];
        RandomNumberGenerator.Create().GetBytes(bytes);
        bytes[^1] &= 0x7F;
        return new BigInteger(bytes);
    }

    public static BigInteger CalculatePublicKey(BigInteger g, BigInteger privateKey, BigInteger p)
    {
        return BigInteger.ModPow(g, privateKey, p);
    }

    public static BigInteger CalculateSharedSecret(BigInteger publicKey, BigInteger privateKey, BigInteger p)
    {
        return BigInteger.ModPow(publicKey, privateKey, p);
    }
}