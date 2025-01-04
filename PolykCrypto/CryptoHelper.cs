using System.Numerics;
using System.Security.Cryptography;

namespace PolykCrypto;

public static class CryptoHelper
{
    public static BigInteger ModInverse(BigInteger a, BigInteger n)
    {
        // Кфы
        BigInteger t = 0, newT = 1;
        // Остатки
        BigInteger r = n, newR = a;

        // Расширенный алгоритм Евклида
        while (newR != 0)
        {
            var q = r / newR;

            (t, newT) = (newT, t - q * newT);
            (r, newR) = (newR, r - q * newR);
        }

        if (r > 1) throw new ArithmeticException("Инверсия отсутсвует, числа не взаимно простые");
        if (t < 0) t += n;

        return t;
    }

    public static BigInteger GeneratePrime(int bits)
    {
        BigInteger prime;
        do
        {
            var bytes = new byte[bits / 8];
            RandomNumberGenerator.Create().GetBytes(bytes);
            
            // Делаем +
            bytes[^1] &= 0x7F;
            
            prime = new BigInteger(bytes);
        } while (!IsPrime(prime));
        
        return prime;
    }

    private static bool IsPrime(BigInteger number, int certainty = 30)
    {
        if (number <= 1) return false;
        if (number == 2 || number == 3) return true;
        if (number % 2 == 0) return false;

        // Здесь ищем количество делений числа на 2(s), чтобы потом представаить n-1 в виде 2^s*d
        var d = number - 1;
        var s = 0;
        for (; d % 2 != 0; s++, d /= 2) { }

        var bytes = new byte[number.ToByteArray().LongLength];
        for (var i = 0; i < certainty; i++)
        {
            // Генерим рандомное a в |2;n-2|
            BigInteger a;
            do
            {
                RandomNumberGenerator.Create().GetBytes(bytes);
                a = new BigInteger(bytes) % (number - 2) + 2;
            } while (a < 2);

            // Считаем x = a^d % n и проверяем условия, если все куд, то скип
            var x = BigInteger.ModPow(a, d, number);
            if (x == 1 || x == number - 1)
                continue;
            
            // Множим x само на себя, если оно в конечном итоге != n-1, то бб
            for (var j = 0; j < s - 1; j++)
            {
                x = BigInteger.ModPow(x, 2, number);
                if (x == number - 1)
                    break;
            }

            if (x != number - 1)
                return false;
        }

        return true;
    }
    
    public static BigInteger GeneratePrimePlusOne(int bitLength, out BigInteger n)
    {
        while (true)
        {
            n = GenerateRandomFactoredNumber(bitLength - 1); // n будет меньше p на 1 бит;
            var p = n + 1;

            if (IsPrime(p))
                return p;
        }
    }

    private static BigInteger GenerateRandomFactoredNumber(int bitLength)
    {
        var random = new Random();
        BigInteger result = 1;

        int a, b;
        if (bitLength >= 500)
        {
            var cMin = 69.72 - 612.5 / Math.Log2(bitLength);
            var cMax = 86.54 - 728.17 / Math.Log2(bitLength);
        
            a = (int)Math.Round(cMin * Math.Log2(bitLength));
            b = (int)Math.Round(cMax * Math.Log2(bitLength));
        }
        else
        {
            a = 2;
            b = 70;
        }

        while (true)
        {
            try
            {
                var primeCount = random.Next(a, b);
                for (var i = 0; i < primeCount; i++)
                {
                    var subBits = bitLength / primeCount;
                    var prime = GeneratePrime(subBits);
                    result *= prime;
                }
                
                break;
            }
            catch (IndexOutOfRangeException e)
            {
                b--;
            }
        }
        
        return result;
    }
    
    public static BigInteger FindPrimitiveRoot(BigInteger p, BigInteger n)
    {
        var factors = Factorize(n);

        for (BigInteger g = 2; g < p; g++)
        {
            var isPrimitiveRoot = factors.All(factor => BigInteger.ModPow(g, n / factor, p) != 1);

            if (isPrimitiveRoot)
                return g;
        }
        
        throw new InvalidOperationException("Первообразный корень не найден");
    }
    
    private static List<BigInteger> Factorize(BigInteger number)
    {
        var factors = new List<BigInteger>();
        BigInteger divisor = 2;

        while (number > 1)
        {
            while (number % divisor == 0)
            {
                factors.Add(divisor);
                number /= divisor;
            }
            divisor++;
        }

        return factors;
    }
}