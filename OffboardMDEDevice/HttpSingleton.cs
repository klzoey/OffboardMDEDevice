// File: HttpClientSingleton.cs
using System;
using System.Net.Http;

namespace OffboardMDEDevice
{
    public sealed class HttpClientSingleton
    {
        private static HttpClient? _httpClientInstance = null;
        private static readonly object _lock = new object();

        private HttpClientSingleton() { }

        public static HttpClient Instance
        {
            get
            {
                lock (_lock)
                {
                    if (_httpClientInstance == null)
                    {
                        _httpClientInstance = new HttpClient();
                    }
                    return _httpClientInstance;
                }
            }
        }
    }
}
