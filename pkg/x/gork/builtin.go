package gork

const corePatterns = `
DATA              .*?
WORD              \w+
DIGITS            \d+
NOTSPACE          \S+
SPACE             \s*
GREEDYDATA        .*
QUOTEDSTRING      "(?:[^"\\]*(\\.[^"\\]*)*)"|\'(?:[^\'\\]*(\\.[^\'\\]*)*)\'
LOGLEVEL          (?:[Aa]lert|ALERT|[Tt]race|TRACE|[Dd]ebug|DEBUG|[Nn]otice|NOTICE|[Ii]nfo|INFO|[Ww]arn?(?:ing)?|WARN?(?:ING)?|[Ee]rr?(?:or)?|ERR?(?:OR)?|[Cc]rit?(?:ical)?|CRIT?(?:ICAL)?|[Ff]atal|FATAL|[Ss]evere|SEVERE|EMERG(?:ENCY)?|[Ee]merg(?:ency)?)

# Numbers
INT                (?:[+-]?(?:[0-9]+))
BASE10NUM          (?:[+-]?(?:[0-9]+(?:\.[0-9]+)?)|\.[0-9]+)
NUMBER             (?:%{BASE10NUM})
BASE16NUM          (?:0[xX]?[0-9a-fA-F]+)
POSINT             \b(?:[1-9][0-9]*)\b
NONNEGINT          \b(?:[0-9]+)\b

# URI

USERNAME           [a-zA-Z0-9._-]+
IPV6               (?:(?:(?:[0-9A-Fa-f]{1,4}:){7}(?:[0-9A-Fa-f]{1,4}|:))|(?:(?:[0-9A-Fa-f]{1,4}:){6}(?::[0-9A-Fa-f]{1,4}|(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(?:(?:[0-9A-Fa-f]{1,4}:){5}(?:(?:(?::[0-9A-Fa-f]{1,4}){1,2})|:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?
IPV4               (?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
IP                 (?:%{IPV6}|%{IPV4})
HOSTNAME           \b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)
IPORHOST           (?:%{IP}|%{HOSTNAME})
HOSTPORT           %{IPORHOST}:%{POSINT}
UNIXPATH           (?:/[\w_%!$@:.,-]?/?)(\S+)?
WINPATH            (?:[A-Za-z]:|\\)(?:\\[^\\?*]*)+
PATH               (?:%{UNIXPATH}|%{WINPATH})
TTY                (?:/dev/(pts|tty([pq])?)(\w+)?/?(?:[0-9]+))
URIPROTO           [A-Za-z]+(?:\+[A-Za-z+]+)?
URIHOST            %{IPORHOST}(?::%{POSINT})?
URIPATH            (?:/[A-Za-z0-9$.+!*'(){},~:;=@#%_\-]*)+
URIPARAM           \?[A-Za-z0-9$.+!*'|(){},~@#%&/=:;_?\-\[\]<>]*
URIPATHPARAM       %{URIPATH}(?:%{URIPARAM})?
URI                %{URIPROTO}://(?:%{USER}(?::[^@]*)?@)?(?:%{URIHOST})?(?:%{URIPATHPARAM})?

# Timestamps
MONTH              \b(?:Jan(?:uary|uar)?|Feb(?:ruary|ruar)?|M(?:a|ä)?r(?:ch|z)?|Apr(?:il)?|Ma(?:y|i)?|Jun(?:e|i)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|O(?:c|k)?t(?:ober)?|Nov(?:ember)?|De(?:c|z)(?:ember)?)\b
MONTHNUM           (?:0?[1-9]|1[0-2])
MONTHNUM2          (?:0[1-9]|1[0-2])
MONTHDAY           (?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9])
DAY                (?:Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?)
YEAR               (?:\d\d){1,2}
HOUR               (?:2[0123]|[01]?[0-9])
MINUTE             (?:[0-5][0-9])
SECOND             (?:(?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?)
TIME               (?:[^0-9]?)%{HOUR}:%{MINUTE}(?::%{SECOND})(?:[^0-9]?)
DATE_US            %{MONTHNUM}[/-]%{MONTHDAY}[/-]%{YEAR}
DATE_EU            %{MONTHDAY}[./-]%{MONTHNUM}[./-]%{YEAR}
ISO8601_TIMEZONE   (?:Z|[+-]%{HOUR}(?::?%{MINUTE}))
ISO8601_SECOND     (?:%{SECOND}|60)
TIMESTAMP_ISO8601  %{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND})?%{ISO8601_TIMEZONE}?
DATE               %{DATE_US}|%{DATE_EU}
DATETIME           %{DATE}[- ]%{TIME}
TZ                 (?:[PMCE][SD]T|UTC)
TIMESTAMP_RFC822   %{DAY} %{MONTH} %{MONTHDAY} %{YEAR} %{TIME} %{TZ}
TIMESTAMP_RFC2822  %{DAY}, %{MONTHDAY} %{MONTH} %{YEAR} %{TIME} %{ISO8601_TIMEZONE}
TIMESTAMP_OTHER    %{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{TZ} %{YEAR}
TIMESTAMP_EVENTLOG %{YEAR}%{MONTHNUM2}%{MONTHDAY}%{HOUR}%{MINUTE}%{SECOND}
SYSLOGTIMESTAMP    %{MONTH} +%{MONTHDAY} %{TIME}
HTTPDATE           %{MONTHDAY}/%{MONTH}/%{YEAR}:%{TIME} %{INT}

# Misc

# Program id on syslog
PROG               [\x21-\x5a\x5c\x5e-\x7e]+

# Aliases
NS   %{NOTSPACE}
QS   %{QUOTEDSTRING}
HOST %{HOSTNAME}
PID  %{POSINT}
USER %{USERNAME}
`
