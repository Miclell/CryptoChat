using System.Numerics;
using System.Text;

namespace PolykCrypto.Aes;

public class AesMessage(BigInteger value, bool isEncrypted = false)
{
    private bool _isEncrypted = isEncrypted;
    
    public static AesMessage FromPlainText(string plainText)
    {
        var bytes = Encoding.UTF8.GetBytes(plainText);
        var value = new BigInteger(bytes, true, true);
        
        return new AesMessage(value, isEncrypted: false);
    }

    public static AesMessage FromHexString(string hexString, bool isEncrypted)
    {
        var value = BigInteger.Parse(hexString, System.Globalization.NumberStyles.HexNumber);
        return new AesMessage(value, isEncrypted);
    }

    public string ToPlainText()
    {
        if (_isEncrypted)
            throw new InvalidOperationException("Сообщение зашифровано. Расшифруйте его перед преобразованием в текст.");
        
        var bytes = value.ToByteArray(true, true);
        return Encoding.UTF8.GetString(bytes).TrimEnd('\0');
    }

    public string ToHexString() => value.ToString("X");

    public BigInteger ToBigInteger() => value;

    public bool IsEncrypted => _isEncrypted;
    
    public AesMessage Encrypt(AesKey key)
    {
        if (_isEncrypted)
            throw new InvalidOperationException("Сообщение уже зашифровано.");
        
        var encryptedValue = Aes.Encrypt(value, key);
        
        _isEncrypted = true;
        
        return new AesMessage(encryptedValue, _isEncrypted);
    }

    public AesMessage Decrypt(AesKey key)
    {
        if (!_isEncrypted)
            throw new InvalidOperationException("Сообщение не зашифровано.");
        
        var decryptedValue = Aes.Decrypt(value, key);
        
        _isEncrypted = false;
        
        return new AesMessage(decryptedValue, _isEncrypted);
    }
}