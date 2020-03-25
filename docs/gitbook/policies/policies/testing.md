# Testing

Alert fatigue and missing obscure edge cases are two common pitfalls of monitoring and alerting tools.

Panther addresses these issues by providing a flexible unit testing framework for policies.

A unit test consists of example input with an expected result to verify policy efficacy.

The example `resource` input is a JSON/YAML map that is used as the input to the `policy` function. However, when building test cases there is no requirement for the test case to populate all the key/value pairs Panther would normally populate. If the policy only checks one key in the resource, it is sufficient to write a test case that populates just that key. The example below shows a policy just checking for the value of the `Encrypted` key, and the example test resource only fills that key.

{% tabs %}
{% tab title="example\_policy.py" %}

```python
def policy(resource):
    return resource['Encrypted']
```

{% endtab %}

{% tab title="test.json" %}

```javascript
{
    "Encrypted": true
}
```

{% endtab %}
{% endtabs %}

## In the Web UI

To build unit tests while writing policies in the web UI, go to the policy editor and scroll down below the policy body to the testing section.

Select the `CREATE YOUR FIRST TEST` button, or the `CREATE TEST` button if tests already exist.

Some default configurations will be displayed, along with an empty JSON editor.

Before jumping into building the test resource, it's important to configure the test properly.

Give the test an appropriate name, select the correct resource type \(if the policy can apply to multiple resource types\), and select whether the policy should evaluate to true or evaluate to false when run against the test resource.

Below the configuration settings for the test, you can begin building the test case as desired. Manually filling out key/value pairs is an option, but tedious and prone to errors. See the **Constructing test resources** section below for alternative options.

To run tests, you can select the `RUN TEST` button to run just the currently selected test, or the `TEST ALL` button to run all tests for the policy. The results of the tests will be displayed below. Remember that `PASS` means the policy returned the expected output when the test was run, not necessarily that the policy returned `True`.

## Testing Locally

Testing locally is very similar to testing in the UI, but with a few additional considerations. To configure tests locally, add the `Tests` field to the policy specification. The `Tests` field expects a list of maps, each map representing one test case. Each map should have exactly the following keys:

| Key              | Description                                                                                                                                                             | Expected Value |
| :--------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------- |
| `ExpectedResult` | Specifies whether the policy should return `True` or `False` when run against the provided `Resource`                                                                   | Boolean        |
| `Name`           | The name of the test                                                                                                                                                    | String         |
| `ResourceType`   | The resource type of the test resource                                                                                                                                  | String         |
| `Resource`       | A JSON or YAML representation of a resource to run the policy against. See the **Constructing test resources** section below for suggestions on how to build this field | Map            |

To run the tests, we highly recommend using the `panther_analysis_tool` tool available [here](https://github.com/panther-labs/panther_analysis_tool). With this tool installed, the following command will test all policies in the specified directory:

`$ panther_analysis_tool test --path path/to/policies`

As a pre-requisite to running the tests, this will also validate all the policy specification files are correctly formatted. The tool outputs the name and results for policy tested, along with a summary of failed/errored tests at the end.

## Constructing test resources

Manually building test cases is tedious and error prone. We suggest one of two alternatives:

1. Open `Cloud Security` > `Resources`, and apply a filter of the resource type you intend to emulate in your test. Select a resource in your environment, and on the `Attributes` card you can copy the full JSON representation of that resource by selecting copy button next to the word `root`.
2. Open the Panther [Resources documentation](../resources/), and navigate to the section for the resource you are trying to emulate. Copy the provided example resource.

Paste this in to the resource editor if you're working in the web UI, or into the `Resource` field if you are working locally. Now you can manually modify the fields relevant to your policy and the specific test case you are trying to emulate.

Option 1 is best when it is practical, as this can provide real test data for your policies. Additionally, it is often the case that you are writing/modifying a policy specifically because of an offending resource in your account. Using that exact resource's JSON representation as your test case can guarantee that similar resources will be caught by your policy in the future.

## Debugging exceptions**

Debugging exceptions can be difficult, as you do not have direct access to the python environment we're running the policies in.

When you see a policy that is showing the state `Error` on a given resource, that means that the policy threw an exception. The best method for troubleshooting these errors is to use option 1 in the **Constructing test resources** section above and create a test case from the resource causing the exception.

Running this test case either locally or in the web UI should provide more context for the issue, and allow you to rapidly modify the policy to debug the exception without having to run the policy against all resources in your environment.
