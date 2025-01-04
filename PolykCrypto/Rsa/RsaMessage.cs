using System.Numerics;
using System.Text;

namespace PolykCrypto.Rsa;

public class RsaMessage(BigInteger value, bool isEncrypted = false)
{
    private bool _isEncrypted = isEncrypted;

    public static RsaMessage FromPlainText(string plainText)
    {
        var bytes = Encoding.UTF8.GetBytes(plainText);
        var value = new BigInteger(bytes, true, true);
        return new RsaMessage(value, isEncrypted: false);
    }

    public static RsaMessage FromHexString(string hexString, bool isEncrypted)
    {
        var value = BigInteger.Parse(hexString, System.Globalization.NumberStyles.HexNumber);
        return new RsaMessage(value, isEncrypted);
    }

    public string ToPlainText()
    {
        if (_isEncrypted)
            throw new InvalidOperationException("Сообщение зашифровано. Расшифруйте его перед преобразованием в текст.");
        
        var bytes = value.ToByteArray(true, true);
        return Encoding.UTF8.GetString(bytes).TrimEnd('\0');
    }

    public string ToHexString() =>
        value.ToString("X");

    public BigInteger ToBigInteger() => value;

    public bool IsEncrypted => _isEncrypted;

    public RsaMessage Encrypt(RsaKey publicKey)
    {
        if (_isEncrypted)
            throw new InvalidOperationException("Сообщение уже зашифровано.");
        
        var encryptedValue = Rsa.Encrypt(value, publicKey);
        
        _isEncrypted = true;
        
        return new RsaMessage(encryptedValue, _isEncrypted);
    }

    public RsaMessage Decrypt(RsaKey privateKey)
    {
        if (!_isEncrypted)
            throw new InvalidOperationException("Сообщение не зашифровано.");
        
        var decryptedValue = Rsa.Decrypt(value, privateKey);
        
        _isEncrypted = false;
        
        return new RsaMessage(decryptedValue, _isEncrypted);
    }
}
