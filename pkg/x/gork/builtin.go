package gork

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// Patterns based on https://github.com/logrusorgru/grokky
// nolint: lll
const BuiltinPatterns = `
DATA              .*?
GREEDYDATA        .*
NOTSPACE          \S+
SPACE             \s*
WORD              \b\w+\b
QUOTEDSTRING      "(?:\\.|[^\\"]+)+"|""|'(?:\\.|[^\\']+)+'|''
HEXDIGIT          [0-9a-fAF]
UUID              %{HEXDIGIT}{8}-(?:%{HEXDIGIT}{4}-){3}%{HEXDIGIT}{12}

# Numbers
INT                [+-]?(?:[0-9]+)
BASE10NUM          [+-]?(?:[0-9]+(?:\.[0-9]+)?)|\.[0-9]+
NUMBER             %{BASE10NUM}
BASE16NUM          (?:0[xX])?%{HEXDIGIT}+
POSINT             \b[1-9][0-9]*\b
NONNEGINT          \b[0-9]+\b

# Network
CISCOMAC   (?:[A-Fa-f0-9]{4}\.){2}[A-Fa-f0-9]{4}
WINDOWSMAC (?:[A-Fa-f0-9]{2}-){5}[A-Fa-f0-9]{2}
COMMONMAC  (?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}
MAC        %{CISCOMAC}|%{WINDOWSMAC}|%{COMMONMAC}
IPV6       \b(?:(?:(?:%{HEXDIGIT}{1,4}:){7}(?:%{HEXDIGIT}{1,4}|:))|(?:(?:%{HEXDIGIT}{1,4}:){6}(?::%{HEXDIGIT}{1,4}|(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(?:(?:%{HEXDIGIT}{1,4}:){5}(?:(?:(?::%{HEXDIGIT}{1,4}){1,2})|:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|((%{HEXDIGIT}{1,4}:){4}(((:%{HEXDIGIT}{1,4}){1,3})|((:%{HEXDIGIT}{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|((%{HEXDIGIT}{1,4}:){3}(((:%{HEXDIGIT}{1,4}){1,4})|((:%{HEXDIGIT}{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|((%{HEXDIGIT}{1,4}:){2}(((:%{HEXDIGIT}{1,4}){1,5})|((:%{HEXDIGIT}{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|((%{HEXDIGIT}{1,4}:){1}(((:%{HEXDIGIT}{1,4}){1,6})|((:%{HEXDIGIT}{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:%{HEXDIGIT}{1,4}){1,7})|((:%{HEXDIGIT}{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\b
IPV4INT    25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9]
IPV4       \b(?:(?:%{IPV4INT})\.){3}(?:%{IPV4INT})\b
IP         %{IPV6}|%{IPV4}
HOSTNAME   \b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)
IPORHOST   %{IP}|%{HOSTNAME}
HOSTPORT   %{IPORHOST}:%{POSINT}

# URI

USERNAME           [a-zA-Z0-9._-]+
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
MONTH              \b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\b
MONTHNUM           0?[1-9]|1[0-2]
MONTHNUM2          0[1-9]|1[0-2]
MONTHDAY           (?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9]
DAY                \b(?:Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?)\b
YEAR               (?:\d\d){1,2}
HOUR               2[0123]|[01]?[0-9]
MINUTE             [0-5][0-9]
SECOND             (?:[0-5]?[0-9]|60)(?:[:.,][0-9]+)?
KITCHEN            %{HOUR}:%{MINUTE}
TIME               %{HOUR}:%{MINUTE}:%{SECOND}
DATE_US            %{MONTHNUM}[/-]%{MONTHDAY}[/-]%{YEAR}
DATE_EU            %{MONTHDAY}[./-]%{MONTHNUM}[./-]%{YEAR}
ISO8601_TIMEZONE   (?:Z|[+-]%{HOUR}(?::?%{MINUTE}))
ISO8601_SECOND     (?:%{SECOND}|60)
TIMESTAMP_ISO8601  %{YEAR}-%{MONTHNUM}-%{MONTHDAY}[T ]%{HOUR}:?%{MINUTE}(?::?%{SECOND})?%{ISO8601_TIMEZONE}?
DATE               %{DATE_US}|%{DATE_EU}
DATETIME           %{DATE}[- ]%{TIME}
TZ                 [A-Z]{3}
TZOFFSET           [+-]\d{4}
TIMESTAMP_RFC822   %{DAY} %{MONTH} %{MONTHDAY} %{YEAR} %{TIME} %{TZ}
TIMESTAMP_RFC2822  %{DAY}, %{MONTHDAY} %{MONTH} %{YEAR} %{TIME} %{ISO8601_TIMEZONE}
TIMESTAMP_OTHER    %{DAY} %{MONTH} %{MONTHDAY} %{TIME} %{TZ} %{YEAR}
TIMESTAMP_EVENTLOG %{YEAR}%{MONTHNUM2}%{MONTHDAY}%{HOUR}%{MINUTE}%{SECOND}
SYSLOGTIMESTAMP    %{MONTH} +%{MONTHDAY} %{TIME}
HTTPDATE           %{MONTHDAY}/%{MONTH}/%{YEAR}:%{TIME} %{TZOFFSET}

# Aliases
NS   %{NOTSPACE}
QS   %{QUOTEDSTRING}
HOST %{HOSTNAME}
PID  %{POSINT}
USER %{USERNAME}
`
