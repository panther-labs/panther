import { History } from 'history';
import { LocationErrorState } from 'Components/utils/ApiErrorFallback';
import { getOperationName } from '@apollo/client/utilities/graphql/getFromAST';
import { ListRemediationsDocument } from 'Components/forms/PolicyForm';
import { RuleTeaserDocument } from 'Pages/AlertDetails';
import { ErrorResponse, onError } from 'apollo-link-error';
import { logError } from 'Helpers/loggers';
import { ApolloLink } from '@apollo/client';

/**
 * A link to react to GraphQL and/or network errors
 */
const createErrorLink = (history: History<LocationErrorState>) => {
  // Define the operations that won't trigger any handler actions or be logged anywhere (those can
  // still be handled by the component independently)
  const silentFailingOperations = [
    getOperationName(ListRemediationsDocument),
    getOperationName(RuleTeaserDocument),
  ];

  return (onError(({ graphQLErrors, networkError, operation }: ErrorResponse) => {
    // If the error is not considered a fail, then don't log it to sentry
    if (silentFailingOperations.includes(operation.operationName)) {
      return;
    }

    if (graphQLErrors) {
      graphQLErrors.forEach(error => {
        logError(error, { operation });
        history.replace(history.location.pathname, { errorType: error.errorType });
      });
    }

    if (networkError) {
      logError(networkError, { operation });
    }
  }) as unknown) as ApolloLink;
};

export default createErrorLink;
