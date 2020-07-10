import faker from 'faker';

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
 * @param isAuthenticated Whether we should mock the `AuthContext` value as if the user was
 * authenticated.
 */
export const mockAuthProviderValue = (isAuthenticated: boolean) => {
  let userInfo = null;
  if (isAuthenticated) {
    userInfo = {
      email: faker.internet.email(),
      email_verified: true,
      given_name: faker.name.firstName(),
      family_name: faker.name.lastName(),
      sub: faker.random.uuid(),
    };
  }

  return {
    isAuthenticated: !!userInfo,
    currentAuthChallengeName: null,
    userInfo,
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
