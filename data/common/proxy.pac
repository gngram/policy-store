function FindProxyForURL(url, host) {
    // Bypass proxy for local addresses
    if (isPlainHostName(host) ||
        dnsDomainIs(host, ".local")) {
        return "DIRECT";
    }

    // Internal corporate network
    if (shExpMatch(host, "*.corp.example.com")) {
        return "PROXY proxy-internal.corp.example.com:8080";
    }

    // Default: go via main proxy
    return "PROXY proxy.example.com:8080; DIRECT";
}
