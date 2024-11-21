function isSuspiciousURL(url) {
    // Check if URL contains IP address instead of a domain
    const ipPattern = /(\d{1,3}\.){3}\d{1,3}/;
    if (ipPattern.test(url)) {
        return { isFake: true, reason: "Contains IP address in place of domain" };
    }

    // Check for common phishing keywords in the URL
    const suspiciousKeywords = ['login', 'secure', 'account', 'update', 'verify', 'banking', 'signin', 'wp-admin'];
    if (suspiciousKeywords.some(keyword => url.toLowerCase().includes(keyword))) {
        return { isFake: true, reason: "Contains suspicious keywords" };
    }

    // Check for domain name pattern that mimics real domains
    if (/(\w+)\.(com|net|org|info)\.(\w+)/.test(url)) {
        return { isFake: true, reason: "Domain pattern resembles a legitimate domain but is fake" };
    }

    // Check for shortened URLs
    const shortenedDomains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co'];
    if (shortenedDomains.some(domain => url.includes(domain))) {
        return { isFake: true, reason: "Shortened URL from popular URL shortener" };
    }

    // Check for unusually long URLs
    if (url.length > 75) {
        return { isFake: true, reason: "URL length is suspiciously long" };
    }

    // Check for unusual TLDs
    const uncommonTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz'];
    const tld = url.split('.').pop().split('/')[0];
    if (uncommonTLDs.includes('.' + tld)) {
        return { isFake: true, reason: "Unusual or suspicious TLD" };
    }

    // Check for hyphens and symbols in the domain
    const domain = url.split('/')[2] || url.split('/')[0];
    if (domain.includes('-') || domain.includes('_')) {
        return { isFake: true, reason: "Domain name contains unusual hyphens or symbols" };
    }

    // Check for domains with only numbers
    const domainName = domain.split('.')[0];
    if (/^\d+$/.test(domainName)) {
        return { isFake: true, reason: "Domain name consists only of numbers" };
    }

    return { isFake: false, reason: "URL appears normal" };
}

function checkURL() {
    const url = document.getElementById("urlInput").value;
    if (url) {
        const result = isSuspiciousURL(url);
        document.getElementById("output").innerHTML = `
            <p><strong>URL:</strong> ${url}</p>
            <p><strong>Suspicious:</strong> ${result.isFake}</p>
            <p><strong>Reason:</strong> ${result.reason}</p>
        `;
    } else {
        document.getElementById("output").innerHTML = "<p>Please enter a URL.</p>";
    }
}