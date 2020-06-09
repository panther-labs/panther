# Datastore

Panther allows rules to cache simple values in a database during rules analysis with built-in helper functions.

## Imports

The first step in using the Panther Datastore is by importing the open source helpers:

```python
import panther_oss_helpers
```

Alternatively, you may import specific functions:

```python
from panther_oss_helpers import increment_counter
```

## Counters

To implement a simple counting rule, use one or more of the following functions:

- `get_counter`: Get the latest counter value
- `increment_counter`: Add to the counter (default of 1)
- `reset_counter`: Reset the counter to 0
- `set_key_expiration`: Set the lifetime of the counter

The example rule below provides a demonstration of using counters.

```python
from panther_oss_helpers import increment_counter, set_key_expiration, reset_counter

def rule(event):
  # Filter to only analyze AccessDenied calls
  if event.get('errorCode') != 'AccessDenied':
      return False

  # Create our counter key, which should be fairly unique
  key = '{}-AccessDeniedCounter'.format(event['userIdentity'].get('arn'))

  # Increment the counter, and then check the current value
  hourly_error_count = increment_counter(key)
  if hourly_error_count == 1:
      set_key_expiration(time.time() + 3600)
  # If it exceeds our threshold, reset and then return an alert
  elif failure_hourly_count >= 10:
      reset_counter(key)
      return True
  return False
```

## String Sets

To keep track of sets of strings, use the following functions:

- `get_string_set`: Get the string set's current value
- `put_string_set`: Overwrite a string set
- `add_to_string_set`: Add one or more strings to a set
- `remove_from_string_set`: Remove one or more strings from a set
- `reset_string_set`: Empty the set

```python
from panther_oss_helpers import add_to_string_set

def rule(event):
  if event['eventName'] != 'AssumeRole':
      return False

  role_arn = event['requestParameters'].get('roleArn')
  if not role_arn:
      return False

  role_arn_key = '{}-UniqueSourceIPs'.format(role_arn)
  ip_addr = event['sourceIPAddress']

  previously_seen_ips = add_to_string_set(role_arn_key, ip_addr)

  # If this the only value, trust on first use
  if len(previously_seen_ips) == 1:
    return False

  if ip_addr not in previously_seen_ips:
    return True

  return False
```

## Testing

{% hint style="warn" %}
Currently, CLI testing does not support mocking function calls.
{% endhint %}
