using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace PolykCrypto.Aes;

public static class Aes
{
    public static BigInteger Encrypt(BigInteger message, AesKey key)
    {
        using var aesAlg = System.Security.Cryptography.Aes.Create();
        aesAlg.Key = key.Key.ToByteArray();
        aesAlg.IV = key.Iv.ToByteArray();

        using var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

        using var msEncrypt = new MemoryStream();
        using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            swEncrypt.Write(Encoding.UTF8.GetString(message.ToByteArray(isUnsigned: true, isBigEndian: true)));
        }
        
        return new BigInteger(msEncrypt.ToArray(), isUnsigned: true, isBigEndian: true);
    }

    public static BigInteger Decrypt(BigInteger cipher, AesKey key)
    {
        using var aesAlg = System.Security.Cryptography.Aes.Create();
        aesAlg.Key = key.Key.ToByteArray();
        aesAlg.IV = key.Iv.ToByteArray();

        using var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

        using var msDecrypt = new MemoryStream(cipher.ToByteArray(isUnsigned: true, isBigEndian: true));
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        string plainText;
        using (var srDecrypt = new StreamReader(csDecrypt))
        {
            plainText = srDecrypt.ReadToEnd();
        }
        
        return new BigInteger(Encoding.UTF8.GetBytes(plainText), true, true);
    }
}