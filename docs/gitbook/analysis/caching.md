# Rule Caching

Panther's real-time analysis engine examines events one-by-one, and sometimes it's helpful to keep state across invocations.

To accommodate stateful checks, rules can cache values by using built-in helper functions.

## Importing the Helpers

The first step is to import the open source helpers library that contains caching functions:

```python
import panther_oss_helpers
```

Alternatively, you may import specific functions:

```python
from panther_oss_helpers import increment_counter
```

## Counters

To implement a counter-based rule, use one or more of the following functions:

- `get_counter`: Get the latest counter value
- `increment_counter`: Add to the counter (default of 1)
- `reset_counter`: Reset the counter to 0
- `set_key_expiration`: Set the lifetime of the counter

The rule below provides a demonstration of using counters.

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
    elif failure_hourly_count >= 10:
    # If it exceeds our threshold, reset and then return an alert
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

    previously_seen_ips = get_string_set(role_arn_key)

    # If this the only value, trust on first use
    if len(previously_seen_ips) == 0:
        add_to_string_set(role_arn_key, ip_addr)
        return False

    if ip_addr not in previously_seen_ips:
        return True

    return False

```

## Testing

{% hint style="warning" %}
Currently, CLI testing does not support mocking function calls.
{% endhint %}
