using DevilGuard.WebService.Misc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DevilGuard.WebService.Network
{
    public sealed class Http : IDisposable
    {
        private readonly HttpClient _client;
        private readonly Uri _url;
        private readonly Dictionary<string, string> _headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private HttpResponseMessage _response;
        private bool _disposed;

        public Http(string url, string overrideRelationId = "", params string[] query)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(url);
            _url = BuildUri(url, query);
            ValidateTransport(_url);

            _client = new HttpClient
            {
                Timeout = HttpOptions.Timeout
            };

            if (!string.IsNullOrWhiteSpace(HttpOptions.ApiAuthorization))
                AddHeader("AA-AUTH", HttpOptions.ApiAuthorization);
            if (!string.IsNullOrWhiteSpace(HttpOptions.ApiToken))
                AddHeader("AA-TOKEN", HttpOptions.ApiToken);
            if (!string.IsNullOrWhiteSpace(overrideRelationId))
                AddHeader("AA-CUSTID", overrideRelationId);
        }

        public int GetHttpCode()
        {
            return _response == null ? 0 : (int)_response.StatusCode;
        }

        public string GetErrorCode()
        {
            if (_response == null || !_response.Headers.TryGetValues("Error-Code", out IEnumerable<string> values))
                return string.Empty;

            return values.FirstOrDefault() ?? string.Empty;
        }

        public void AddHeader(string key, string value)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(key);
            _headers[key] = value ?? string.Empty;
        }

        public dynamic GETJSON(Type typeOf)
        {
            string json = GET();
            ProcessStatusCodes();
            return Serializer.Deserialize(json, typeOf);
        }

        public void POSTJSON(object input)
        {
            POST(Serializer.Serialize(input));
            ProcessStatusCodes();
        }

        public dynamic POSTJSON(object input, Type typeOf)
        {
            string json = POST(Serializer.Serialize(input));
            ProcessStatusCodes();
            return Serializer.Deserialize(json, typeOf);
        }

        public void PUTJSON(object input)
        {
            PUT(Serializer.Serialize(input));
            ProcessStatusCodes();
        }

        public dynamic PUTJSON(object input, Type typeOf)
        {
            string json = PUT(Serializer.Serialize(input));
            ProcessStatusCodes();
            return Serializer.Deserialize(json, typeOf);
        }

        public string GET()
        {
            return GetAsync().GetAwaiter().GetResult();
        }

        public string POST(string message)
        {
            return PostAsync(message).GetAwaiter().GetResult();
        }

        public string PUT(string message)
        {
            return PutAsync(message).GetAwaiter().GetResult();
        }

        public string GetPageContent()
        {
            return GET();
        }

        public Task<string> GetAsync(CancellationToken cancellationToken = default)
        {
            return SendAsync(HttpMethod.Get, null, cancellationToken);
        }

        public Task<string> PostAsync(string message, CancellationToken cancellationToken = default)
        {
            return SendAsync(HttpMethod.Post, message, cancellationToken);
        }

        public Task<string> PutAsync(string message, CancellationToken cancellationToken = default)
        {
            return SendAsync(HttpMethod.Put, message, cancellationToken);
        }

        public void ProcessStatusCodes()
        {
            _response?.EnsureSuccessStatusCode();
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            _response?.Dispose();
            _client.Dispose();
            _disposed = true;
        }

        private async Task<string> SendAsync(HttpMethod method, string message, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            using HttpRequestMessage request = new HttpRequestMessage(method, _url);
            request.Headers.Accept.ParseAdd("application/json");
            foreach (KeyValuePair<string, string> header in _headers)
                request.Headers.TryAddWithoutValidation(header.Key, header.Value);

            if (message != null)
                request.Content = new StringContent(message, Encoding.UTF8, "application/json");

            _response?.Dispose();
            _response = await _client.SendAsync(request, HttpCompletionOption.ResponseContentRead, cancellationToken)
                .ConfigureAwait(false);

            return await _response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        }

        private static Uri BuildUri(string url, string[] query)
        {
            Uri uri;
            if (!Uri.TryCreate(url, UriKind.Absolute, out uri))
            {
                if (HttpOptions.BaseAddress == null)
                    throw new InvalidOperationException("Set HttpOptions.BaseAddress before using relative service URLs.");
                uri = new Uri(HttpOptions.BaseAddress, url);
            }

            if (query == null || query.Length == 0)
                return uri;

            UriBuilder builder = new UriBuilder(uri);
            string newQuery = string.Join("&", query
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(EncodeQueryEntry));
            builder.Query = string.IsNullOrWhiteSpace(builder.Query)
                ? newQuery
                : $"{builder.Query.TrimStart('?')}&{newQuery}";
            return builder.Uri;
        }

        private static string EncodeQueryEntry(string entry)
        {
            int separator = entry.IndexOf('=');
            if (separator < 0)
                return Uri.EscapeDataString(entry);

            string key = entry.Substring(0, separator);
            string value = entry.Substring(separator + 1);
            return Uri.EscapeDataString(key) + "=" + Uri.EscapeDataString(value);
        }

        private static void ValidateTransport(Uri uri)
        {
            if (uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                return;

            bool local = uri.IsLoopback || uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase);
            if (!(local && HttpOptions.AllowInsecureLocalhost))
                throw new InvalidOperationException("Devil-Guard web-service traffic must use HTTPS.");
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(Http));
        }
    }
}
