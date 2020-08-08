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

import { UserInfo } from 'Components/utils/AuthContext';

export const buildUserInfo = (overrides?: Partial<UserInfo>) => ({
  email: 'test@test.test',
  emailVerified: true,
  givenName: 'TestName',
  familyName: 'TestSurname',
  id: '1234-1234-1234-1234',
  ...overrides,
});

/**
 * Helper function that mocks the "core" shape of all auth-related actions. Each of them has an
 * onSuccess/onError callback (among other params)
 * */
const mockFunctionHelper = jest.fn<
  Promise<any>,
  { onSuccess?: () => void; onError?: (err: any) => void }[]
>(({ onSuccess }) => Promise.resolve().then(() => onSuccess && onSuccess()));

/**
 * The value that `AuthContext` would get. We don't test auth-related actions in integration tests
 * (as opposed to E2E), so we can safely mock the "end" state, which is either a logged-out user
 * or a logged-in user
 *
 * @param userInfo The information of the authenticated user. A falsy value has the user as not
 * authenticated
 */
export const mockAuthProviderValue = (userInfo: UserInfo) => {
  return {
    isAuthenticated: !!userInfo,
    currentAuthChallengeName: null,
    userInfo: userInfo || null,
    refetchUserInfo: mockFunctionHelper,
    signIn: mockFunctionHelper,
    confirmSignIn: mockFunctionHelper,
    signOut: mockFunctionHelper,
    setNewPassword: mockFunctionHelper,
    changePassword: mockFunctionHelper,
    resetPassword: mockFunctionHelper,
    forgotPassword: mockFunctionHelper,
    requestTotpSecretCode: mockFunctionHelper,
    verifyTotpSetup: mockFunctionHelper,
  };
};
