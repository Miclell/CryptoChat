using System.Numerics;

namespace PolykCrypto.Rsa;

public class RsaKey(BigInteger exponent, BigInteger modulus)
{
    public BigInteger Exponent { get; } = exponent;
    public BigInteger Modulus { get; } = modulus;

    public override string ToString() => 
        $"{Exponent.ToString("X")}|{Modulus.ToString("X")}";

    public static RsaKey FromString(string keyString)
    {
        var parts = keyString.Split('|');
        if (parts.Length != 2) throw new FormatException("Неверный формат ключа");

        var exponent = BigInteger.Parse(parts[0], System.Globalization.NumberStyles.HexNumber);
        var modulus = BigInteger.Parse(parts[1], System.Globalization.NumberStyles.HexNumber);

        return new RsaKey(exponent, modulus);
    }
}