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

import { History } from 'history';
import { LocationErrorState } from 'Components/utils/ApiErrorFallback';
import { getOperationName } from 'apollo-utilities';
import { ListRemediationsDocument } from 'Components/forms/PolicyForm';
import { GetRuleSummaryDocument } from 'Pages/AlertDetails/RuleAlertDetails';
import { ErrorResponse, onError } from 'apollo-link-error';
import { logError } from 'Helpers/errors';
import { ApolloLink } from '@apollo/client';

/**
 * A link to react to GraphQL and/or network errors
 */
const createErrorLink = (history: History<LocationErrorState>) => {
  // Define the operations that won't trigger any handler actions or be logged anywhere (those can
  // still be handled by the component independently)
  const silentFailingOperations = [
    getOperationName(ListRemediationsDocument),
    getOperationName(GetRuleSummaryDocument),
  ];

  return (onError(({ graphQLErrors, networkError, operation }: ErrorResponse) => {
    // If the error is not considered a fail, then don't log it to sentry
    if (silentFailingOperations.includes(operation.operationName)) {
      return;
    }

    if (graphQLErrors) {
      graphQLErrors.forEach(error => {
        logError(error, { operation });
        history.replace({
          ...history.location,
          state: {
            ...history.location.state,
            errorType: error.errorType,
          },
        });
      });
    }

    if (networkError) {
      logError(networkError, { operation });
    }
  }) as unknown) as ApolloLink;
};

export default createErrorLink;
