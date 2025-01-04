using System.Numerics;
using System.Security.Cryptography;

namespace PolykCrypto.Aes;

public class AesKey(BigInteger key, BigInteger iv)
{
    public BigInteger Key { get; } = key;
    public BigInteger Iv { get; } = iv;
    
    public override string ToString() => 
        $"{Key.ToString("X")}|{Iv.ToString("X")}";

    public static AesKey From4096OneKeyBigInteger(BigInteger key)
    {
        var byteKey = key.ToByteArray();
        var hashedKey = new BigInteger(SHA256.HashData(byteKey));
        var iv = new BigInteger(SHA1.HashData(byteKey).Take(16).ToArray());

        return new AesKey(hashedKey, iv);
    }

    public static AesKey FromString(string keyString)
    {
        var parts = keyString.Split('|');
        if (parts.Length != 2) throw new FormatException("Неверный формат ключа");
        
        var key = BigInteger.Parse(parts[0], System.Globalization.NumberStyles.HexNumber);
        var iv = BigInteger.Parse(parts[1], System.Globalization.NumberStyles.HexNumber);
        
        return new AesKey(key, iv);
    }
}