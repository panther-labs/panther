# Role-Based Access Control
Role-Based Access Control (RBAC) allows enterprise deployments to enforce least privilege access -
users are assigned roles with fully customizable permission sets.

## Roles
In Panther Enterprise, a *role* is a configurable set of permissions and every user is assigned
exactly one role. By default, the following 3 roles are created for you:

<img src="docs/img/rbac-default-roles.png" alt="Default Roles"/>
<p align="center"><i>Default Roles:</i> Admin, Analyst, AnalystReadOnly</p>

* The "Admin" role will be automatically assigned to all existing users when upgrading from the
community edition and has all available permissions.
* The "Analyst" role can use all of the cloud security and log analysis features, but can't view or
modify settings.
* The "AnalystReadOnly" role can view resources and alerts and Python code, but can't change anything.

All roles (including the default ones above) are fully customizable by any user with UserModify permissions:

* You can create as many roles as you want
* Roles can be renamed as long as the names are unique
* Role permissions can be changed as long as at least one user has UserModify permissions
* Roles can be deleted as long as no users are currently assigned to them

<img src="docs/img/rbac-role-edit.png" alt="Role Edit"/>
<p align="center">A subset of the role edit page</p>
