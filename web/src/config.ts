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

import * as Yup from 'yup';
import Auth from '@aws-amplify/auth';

// Initialize the Cognito client to the correct user pool
Auth.configure({
  userPoolId: process.env.WEB_APPLICATION_USER_POOL_ID,
  userPoolWebClientId: process.env.WEB_APPLICATION_USER_POOL_CLIENT_ID,
  region: process.env.AWS_REGION,
});

// Set the defaults for some of the pre-implemented yup funcs
Yup.setLocale({
  mixed: {
    required: 'This field is required',
  },
});

// Add a custom `unique` method on Yup that's gonna validate that an array of items doesn't contain
// duplicates. The duplicates can be entire items or only a certain field (based on the `mapper` param
// that's passed.
Yup.addMethod(Yup.array, 'unique', function method(this, message = 'No duplicates allowed', key) {
  return this.test('unique', message, function testFunc(items) {
    const hasUniqueIntegrity = items.length === new Set(items.map(i => (key ? i[key] : i))).size;
    if (!hasUniqueIntegrity) {
      // if there is a duplicate, create an error on the last item in the array
      return this.createError({ path: `${this.path}[${items.length - 1}].${key}`, message });
    }
    return true;
  });
});
