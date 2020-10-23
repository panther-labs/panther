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

import React from 'react';
import Auth, { CognitoUser } from '@aws-amplify/auth';
import { USER_INFO_STORAGE_KEY } from 'Source/constants';
import { pantherConfig } from 'Source/config';
import storage from 'Helpers/storage';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';

// Challenge names from Cognito from
// https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RespondToAuthChallenge.html#API_RespondToAuthChallenge_RequestSyntax
export enum CHALLENGE_NAMES {
  MFA_SETUP = 'MFA_SETUP',
  NEW_PASSWORD_REQUIRED = 'NEW_PASSWORD_REQUIRED',
  SOFTWARE_TOKEN_MFA = 'SOFTWARE_TOKEN_MFA',
}

interface AuthError {
  /** unique error code */
  code: string;

  /** verbose exception that happened */
  message: string;

  /** optional | name of the exception, usually just the code itself */
  name?: string;
}

export interface EnhancedCognitoUser extends CognitoUser {
  challengeParam: {
    userAttributes: {
      /* eslint-disable  camelcase  */
      email: string;
      given_name?: string;
      family_name?: string;
      /* eslint-enable  camelcase  */
    };
  };
  challengeName?: CHALLENGE_NAMES;
  attributes: {
    /* eslint-disable  camelcase  */
    email: string;
    email_verified: boolean;
    family_name?: string;
    given_name?: string;
    sub: string;
    /* eslint-enable  camelcase  */
  };
  signInUserSession?: {
    accessToken?: {
      payload: {
        'cognito:users'?: string[];
      };
    };
  };
}

export type UserInfo = {
  id: string;
  email: string;
  emailVerified: boolean;
  givenName?: string;
  familyName?: string;
};

interface SignOutParams {
  global?: boolean;
  onSuccess?: () => void;
  onError?: (err: AuthError) => void;
}

interface SignInParams {
  email: string;
  password: string;
  onSuccess?: () => void;
  onError?: (err: AuthError) => void;
}

interface ConfirmSignInParams {
  mfaCode: string;
  onSuccess?: () => void;
  onError?: (err: AuthError) => void;
}

interface VerifyTotpSetupParams {
  mfaCode: string;
  onSuccess?: () => void;
  onError?: (err: AuthError) => void;
}

interface SetNewPasswordParams {
  newPassword: string;
  onSuccess?: () => void;
  onError?: (err: AuthError) => void;
}

interface ChangePasswordParams {
  oldPassword: string;
  newPassword: string;
  onSuccess?: () => void;
  onError?: (err: AuthError) => void;
}

interface ResetPasswordParams {
  token: string;
  email: string;
  newPassword: string;
  onSuccess?: () => void;
  onError?: (err: AuthError) => void;
}

interface ForgotPasswordParams {
  email: string;
  onSuccess?: () => void;
  onError?: (err: AuthError) => void;
}

interface RefetchUserInfoParams {
  onSuccess?: () => void;
  onError?: (err: AuthError) => void;
}

/*
  We intentionaly use `undefined` and `null` in the interface below to showcase the possible values
 */
export interface AuthContextValue {
  isAuthenticated: boolean | undefined;
  currentAuthChallengeName: CHALLENGE_NAMES | null;
  userInfo: UserInfo | null;
  signIn: (params: SignInParams) => Promise<void>;
  confirmSignIn: (params: ConfirmSignInParams) => Promise<void>;
  refetchUserInfo: (params?: RefetchUserInfoParams) => Promise<void>;
  setNewPassword: (params: SetNewPasswordParams) => Promise<void>;
  verifyTotpSetup: (params: VerifyTotpSetupParams) => Promise<void>;
  requestTotpSecretCode: () => Promise<string>;
  signOut: (params?: SignOutParams) => Promise<void>;
  changePassword: (params: ChangePasswordParams) => Promise<void>;
  resetPassword: (params: ResetPasswordParams) => Promise<void>;
  forgotPassword: (params: ForgotPasswordParams) => Promise<void>;
}

const AuthContext = React.createContext<AuthContextValue>(undefined);

// We check if there was a previous session for this user already present. We use that to
// *OPTIMISTICALLY* decide whether the user should be considered authenticated on mount time. We
// say optimistically as the token may have expired by the time they revisit. This will be handled
// in the Amplify, since the `isAuthenticated` flag just decides which screens to show.
const previousUserSessionExists = Boolean(
  storage.local.read(
    `CognitoIdentityServiceProvider.${pantherConfig.WEB_APPLICATION_USER_POOL_CLIENT_ID}.LastAuthUser`
  )
);

const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // Stores whether the system should consider the current user as logged-in or not. This can be
  // true without `authUser` being present, since `authUser` comes asynchronously from Cognito, thus
  // it's *always* initially `null`.
  const [isAuthenticated, setAuthenticated] = React.useState(previousUserSessionExists);
  // Stores the currently authenticated user of the app
  const [authUser, setAuthUser] = React.useState<EnhancedCognitoUser | null>(null);

  /*
   * Isolate the userInfo from the user. This is an object that will persist in our storage so that
   * we can boot up the user's information (name, token, etc.) the next time he visits the app. The
   * value changes whenever the cognito session changes
   */
  const userInfo = React.useMemo<UserInfo>(() => {
    // if a user is present, derive the user info from him
    // Check if this is calculated
    if (authUser?.attributes) {
      // eslint-disable-next-line  camelcase
      const { family_name, given_name, sub, email_verified, ...rest } = authUser.attributes;
      return {
        ...rest,
        id: sub,
        familyName: family_name,
        givenName: given_name,
        emailVerified: email_verified,
      };
    }

    // if no user is present, attempt to return data from the stored session. This is true when
    // the request to get the cognito `authUser` is in flight and hasn't returned yet
    if (isAuthenticated) {
      return storage.local.read<UserInfo>(USER_INFO_STORAGE_KEY);
    }

    // if no prev session exists and the user is not logged-in, then there is no userInfo
    return null;
  }, [isAuthenticated, authUser]);

  /**
   * Every time the `userInfo` is updated, we want to store this value in our storage in order to
   * remember it for future logins. If we don't do that, then we don't have a way of knowing the
   * user on mount time.
   */
  React.useEffect(() => {
    if (userInfo) {
      storage.local.write(USER_INFO_STORAGE_KEY, userInfo);
    } else {
      storage.local.delete(USER_INFO_STORAGE_KEY);
    }
  }, [userInfo]);

  /**
   * @public
   * Signs the user in our system
   *
   */
  const signIn = React.useCallback(
    async ({ email, password, onSuccess = () => {}, onError = () => {} }: SignInParams) => {
      try {
        const signedInUser = await Auth.signIn(email, password);

        // We are forcing an attribute email, since Cognito doesn't return the email of the user
        // until they pass the MFA challenge.
        signedInUser.attributes = { email };
        setAuthUser(signedInUser);

        onSuccess();
      } catch (err) {
        onError(err as AuthError);
      }
    },
    []
  );

  /**
   * @public
   * Signs the user out. Can be global sign out (all devices) or just local (this device only)
   *
   */
  const signOut = React.useCallback(
    ({ global = false, onSuccess = () => {}, onError = () => {} }: SignOutParams = {}) => {
      return Auth.signOut({ global })
        .then(onSuccess)
        .catch(onError)
        .finally(() => {
          setAuthUser(null);
          setAuthenticated(false);
        });
    },
    []
  );

  /**
   *
   * @public
   * Verifies that the user is not an imposter by verifying the TOTP challenge that the user was
   * presented with. This function verifies that the one-time password was indeed correct
   *
   */
  const confirmSignIn = React.useCallback(
    async ({ mfaCode, onSuccess = () => {}, onError = () => {} }: ConfirmSignInParams) => {
      try {
        await Auth.confirmSignIn(authUser, mfaCode, 'SOFTWARE_TOKEN_MFA');

        const confirmedUser = await Auth.currentAuthenticatedUser();
        setAuthUser(confirmedUser);
        setAuthenticated(true);
        trackEvent({ event: EventEnum.SignedIn, src: SrcEnum.Auth });
        onSuccess();
      } catch (err) {
        trackError({ event: TrackErrorEnum.FailedMfa, src: SrcEnum.Auth });
        onError(err as AuthError);
      }
    },
    [authUser]
  );

  /**
   *
   * @public
   * Verifies that the user has correctly setup the TOTP
   *
   */
  const verifyTotpSetup = React.useCallback(
    async ({ mfaCode, onSuccess = () => {}, onError = () => {} }: VerifyTotpSetupParams) => {
      try {
        await Auth.verifyTotpToken(authUser, mfaCode);
        await Auth.setPreferredMFA(authUser, 'TOTP');
        // NOTE: User is confirmed at this point so we can go ahead and log in user here
        const confirmedUser = await Auth.currentAuthenticatedUser();
        setAuthUser(confirmedUser);
        setAuthenticated(true);
        onSuccess();
      } catch (err) {
        onError(err as AuthError);
      }
    },
    [authUser]
  );

  /**
   * @public
   * Sets up TOTP for the user by requesting a new secret code to be used as part of the oauth url
   */
  const requestTotpSecretCode = React.useCallback(() => Auth.setupTOTP(authUser), [authUser]);

  /**
   * @public
   * Sets a new password for the user when he has a temporary one
   *
   */
  const setNewPassword = React.useCallback(
    async ({ newPassword, onSuccess = () => {}, onError = () => {} }: SetNewPasswordParams) => {
      try {
        const userWithUpdatedPassword = await Auth.completeNewPassword(authUser, newPassword, {});

        // simply clone it (that's what this code does) so the ref changes in order to trigger
        // a React re-render (amplify mutates while react plays with immutable structures)
        setAuthUser(
          Object.assign(
            Object.create(Object.getPrototypeOf(userWithUpdatedPassword)),
            userWithUpdatedPassword
          )
        );

        onSuccess();
      } catch (err) {
        onError(err as AuthError);
      }
    },
    [authUser]
  );

  /**
   * @public
   * Changes the current password for the user. This is a different workflow than `setPassword`,
   * since the user doesn't have a temporary password here and he also needs to provide his old
   * password
   */
  const changePassword = React.useCallback(
    async ({
      oldPassword,
      newPassword,
      onSuccess = () => {},
      onError = () => {},
    }: ChangePasswordParams) => {
      try {
        await Auth.changePassword(authUser, oldPassword, newPassword);

        onSuccess();
      } catch (err) {
        onError(err as AuthError);
      }
    },
    [authUser]
  );

  /**
   * @public
   * Resets the current password for the user to the value he has given. This is a different
   * workflow than `setPassword` or `changePassword` since the user doesn't have knowledge of his
   * current password, except for a reset link that he received through an email. This link
   * contained the reset token used below
   */
  const resetPassword = React.useCallback(
    async ({
      email,
      token,
      newPassword,
      onSuccess = () => {},
      onError = () => {},
    }: ResetPasswordParams) => {
      try {
        await Auth.forgotPasswordSubmit(email, token, newPassword);

        onSuccess();
      } catch (err) {
        onError(err as AuthError);
      }
    },
    []
  );

  /**
   * @public
   * A method to initiate a forgot password request. This will send the user an email containing
   * a link to reset his password
   */
  const forgotPassword = React.useCallback(
    async ({ email, onSuccess = () => {}, onError = () => {} }: ForgotPasswordParams) => {
      try {
        await Auth.forgotPassword(email);

        onSuccess();
      } catch (err) {
        onError(err as AuthError);
      }
    },
    []
  );

  /**
   * @public
   * A method to refetch user info in order to update state when a user edits self
   */
  const refetchUserInfo = React.useCallback(
    async ({ onSuccess = () => {}, onError = () => {} }: RefetchUserInfoParams = {}) => {
      try {
        const currentUserInfo = await Auth.currentAuthenticatedUser({ bypassCache: true });
        setAuthUser(currentUserInfo);
        onSuccess();
      } catch (err) {
        onError(err as AuthError);
        signOut();
      }
    },
    []
  );

  /**
   * During mount time only, after having - possibly - set up the Auth configuration, attempt to
   * boot up the user from a previous session
   */
  React.useEffect(() => {
    if (previousUserSessionExists) {
      Auth.currentAuthenticatedUser({ bypassCache: true })
        .then(setAuthUser)
        .catch(() => signOut());
    }
  }, []);

  /**
   * @public
   * The `isAuthenticated` has an undefined value whenever we haven't yet figured out if the user
   * is or isn't authenticated cause we are on the process of examining his token. It has a boolean
   * value in any other case
   */
  const contextValue = React.useMemo(
    () => ({
      isAuthenticated,
      currentAuthChallengeName: authUser?.challengeName || null,
      userInfo,
      refetchUserInfo,

      signIn,
      confirmSignIn,
      signOut,

      setNewPassword,
      changePassword,
      resetPassword,
      forgotPassword,

      requestTotpSecretCode,
      verifyTotpSetup,
    }),
    [isAuthenticated, authUser]
  );

  return <AuthContext.Provider value={contextValue}>{children}</AuthContext.Provider>;
};

const MemoizedAuthProvider = React.memo(AuthProvider);

export { AuthContext, MemoizedAuthProvider as AuthProvider };
