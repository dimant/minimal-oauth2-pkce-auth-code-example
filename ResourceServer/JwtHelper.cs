using System.Text;

namespace ResourceServer
{
    public static class JwtHelper
    {
        /// <summary>
        /// Decodes a Base64Url encoded string.
        /// 
        /// Educational Note on Base64Url:
        /// Standard Base64 uses characters: A-Z, a-z, 0-9, +, /, =
        /// Base64Url (RFC 4648) uses URL-safe variants: A-Z, a-z, 0-9, -, _
        /// This avoids conflicts with URL special characters.
        /// 
        /// Conversion:
        /// - Replace '-' with '+' (minus to plus)
        /// - Replace '_' with '/' (underscore to slash)
        /// - Restore padding '=' at the end if needed (standard Base64 requires length % 4 == 0)
        /// </summary>
        public static string Base64UrlDecode(string input)
        {
            // Convert URL-safe base64 to standard base64
            var base64 = input.Replace("-", "+").Replace("_", "/");
            
            // Add padding if necessary (standard Base64 requires length to be multiple of 4)
            while (base64.Length % 4 != 0)
            {
                base64 += "=";
            }

            var bytes = Convert.FromBase64String(base64);
            return Encoding.UTF8.GetString(bytes);
        }

        /// <summary>
        /// Encodes bytes to Base64Url format.
        /// 
        /// Educational Note:
        /// This converts standard Base64 to URL-safe Base64Url format by:
        /// 1. Converting to standard Base64: A-Z, a-z, 0-9, +, /, =
        /// 2. Replacing '+' with '-' and '/' with '_' (URL-safe alternatives)
        /// 3. Removing padding '=' characters (not needed in URLs and can be ambiguous)
        /// </summary>
        public static string Base64UrlEncode(byte[] input)
        {
            var base64 = Convert.ToBase64String(input);
            return base64.Replace("+", "-")
                         .Replace("/", "_")
                         .TrimEnd('=');
        }

        /// <summary>
        /// Timing-safe string comparison to prevent timing attacks.
        /// 
        /// Security Educational Note - Timing Attacks:
        /// A naive string comparison using == returns false on the first mismatched character.
        /// An attacker could measure how long the comparison takes to gradually guess a valid signature:
        /// - If first character wrong: very fast rejection (~1 char comparison)
        /// - If first char right but second wrong: slower rejection (~2 char comparisons)
        /// - This timing information leaks data about valid signatures!
        /// 
        /// Mitigation:
        /// This method ALWAYS compares all characters, regardless of early mismatches.
        /// The time taken is constant (depends on string length, not content).
        /// This prevents attackers from using timing to guess valid signatures.
        /// </summary>
        public static bool TimingSafeEquals(string a, string b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }

            bool result = true;
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                {
                    result = false;
                }
            }

            return result;
        }
    }
}
