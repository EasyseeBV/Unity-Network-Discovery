using UnityEngine;

public static class CommandHash
{
    public static uint ComputeHash(string text)
    {
        unchecked
        {
            const uint fnvPrime = 0x01000193;
            var hash = 0x811C9DC5;
            foreach (var c in text)
            {
                hash ^= c;
                hash *= fnvPrime;
            }

            return hash;
        }
    }
}