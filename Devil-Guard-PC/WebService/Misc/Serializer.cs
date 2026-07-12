using System;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace DevilGuard.WebService.Misc
{
    internal static class Serializer
    {
        private static readonly JsonSerializerOptions Options = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = false
        };

        public static string Serialize(object input)
        {
            ArgumentNullException.ThrowIfNull(input);
            return JsonSerializer.Serialize(input, input.GetType(), Options);
        }

        public static dynamic Deserialize(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return null;

            return JsonNode.Parse(input);
        }

        public static object Deserialize(string input, Type type)
        {
            ArgumentNullException.ThrowIfNull(type);
            if (string.IsNullOrWhiteSpace(input))
                return Activator.CreateInstance(type);

            return JsonSerializer.Deserialize(input, type, Options) ?? Activator.CreateInstance(type);
        }
    }
}
