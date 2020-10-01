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

import { ErrorResponse } from 'apollo-link-error';
import { ERROR_REPORTING_CONSENT_STORAGE_KEY } from 'Source/constants';
import { pantherConfig } from 'Source/config';
import storage from 'Helpers/storage';
import { Operation } from '@apollo/client';

interface ErrorData {
  operation?: Operation;
  extras?: {
    [key: string]: any;
  };
}

/**
 * Logs an error to sentry. Accepts *optional* additional arguments for easier debugging
 */
export const logError = (error: Error | ErrorResponse, { operation, extras }: ErrorData = {}) => {
  // On some environments we have sentry disabled
  const sentryDsn = process.env.SENTRY_DSN;
  const sentryRelease = pantherConfig.PANTHER_VERSION;
  if (!sentryDsn) {
    return;
  }

  // If he user hasn't  allowed us, then don't report the error
  // For information on how does this value ended up in the Storage (and how it syncs itself with
  // the latest updates), see /web/src/client.ts
  if (storage.local.read<boolean>(ERROR_REPORTING_CONSENT_STORAGE_KEY) !== true) {
    return;
  }

  import(/* webpackChunkName: "sentry" */ '@sentry/browser').then(Sentry => {
    // We don't wanna initialize before any error occurs so we don't have to un-necessarily download
    // the sentry chunk at the user's device. `Init` method is idempotent, meaning that no matter
    // how many times we call it, it won't override anything. In addition it adds 0 thread overhead.
    Sentry.init({ dsn: sentryDsn, release: sentryRelease });
    // As soon as sentry is init, we add a scope to the error. Adding the scope here makes sure that
    // we don't have to manage the scopes on login/logout events
    Sentry.withScope(scope => {
      // If we have access to the operation that occurred, then we store this info for easier debugging
      if (operation) {
        scope.setTag('operationName', operation.operationName);
      }

      // If we have a custom stacktrace to share we add it here
      if (extras) {
        scope.setExtras(extras);
      }

      // Log the actual error
      Sentry.captureException(error);
    });
  });
};
