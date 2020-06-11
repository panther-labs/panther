# AWS Update Account Password Policy

#### Remediation Id

`AWS.IAM.UpdateAccountPasswordPolicy`

#### Description

Remediation that sets an account's password policy.

#### Resource Parameters

| Name        | Description        |
| :---------- | :----------------- |
| `AccountId` | The AWS Account Id |

#### Additional Parameters

<table>
  <thead>
    <tr>
      <th style="text-align:left">Name</th>
      <th style="text-align:left">Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left"><code>MinimumPasswordLength</code>
      </td>
      <td style="text-align:left">The minimum number of characters allowed in an IAM user password</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>RequireSymbols</code>
      </td>
      <td style="text-align:left">
        <p>Boolean that specifies whether IAM user passwords must contain at least
          one of the following non-alphanumeric characters:</p>
        <p><code>! @ # $ % ^ * ( ) _ + - = [ ] { } | &apos;</code> 
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left"><code>RequireNumbers</code>
      </td>
      <td style="text-align:left">Boolean that specifies whether IAM user passwords must contain at least
        one numeric character (0 to 9)</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>RequireUppercaseCharacters</code>
      </td>
      <td style="text-align:left">Boolean that specifies whether IAM user passwords must contain at least
        one uppercase character from the ISO basic Latin alphabet (A to Z)</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>RequireLowercaseCharacters</code>
      </td>
      <td style="text-align:left">Boolean that specifies whether IAM user passwords must contain at least
        one lowercase character from the ISO basic Latin alphabet (a to z)</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>AllowUsersToChangePassword</code>
      </td>
      <td style="text-align:left">Boolean that specifies if IAM users in the account can change their own
        passwords</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>MaxPasswordAge</code>
      </td>
      <td style="text-align:left">The number of days that an IAM user password is valid</td>
    </tr>
    <tr>
      <td style="text-align:left"><code>PasswordReusePrevention</code>
      </td>
      <td style="text-align:left">Specifies the number of previous passwords that IAM users are prevented
        from reusing</td>
    </tr>
  </tbody>
</table>#### References

- [https://docs.aws.amazon.com/cli/latest/reference/iam/update-account-password-policy.html](https://docs.aws.amazon.com/cli/latest/reference/iam/update-account-password-policy.html)
