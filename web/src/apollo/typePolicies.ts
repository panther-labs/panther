import { Query, ResolversParentTypes } from 'Generated/schema';
import storage from 'Helpers/storage';
import { ERROR_REPORTING_CONSENT_STORAGE_KEY } from 'Source/constants';
import {
  Reference,
  FieldPolicy,
  FieldReadFunction,
  TypePolicies as ApolloTypePolicies,
} from '@apollo/client';

type FieldValues<T> =
  | FieldPolicy<T, T, T | Reference | undefined>
  | FieldReadFunction<T, T | Reference | undefined>;

type TypePolicy<T> = {
  keyFields?: keyof T | (keyof T)[] | false;
  fields?: Partial<
    {
      [P in keyof T]: FieldValues<T[P]>;
    }
  >;
};

export type TypePolicies = Partial<
  {
    [T in keyof ResolversParentTypes]: TypePolicy<ResolversParentTypes[T]>;
  }
> & {
  Query: TypePolicy<Query>;
};

const typePolicies: TypePolicies = {
  Query: {
    fields: {
      getComplianceIntegration(existingData, { args, toReference }) {
        return (
          existingData ||
          toReference({ __typename: 'ComplianceIntegration', integrationId: args.id })
        );
      },
      getLogIntegration(existingData, { args, toReference }) {
        return (
          existingData || toReference({ __typename: 'LogIntegration', integrationId: args.id })
        );
      },
      getLogDatabase(existingData, { args, toReference }) {
        return existingData || toReference({ __typename: 'LogDatabase', name: args.name });
      },
      getLogDatabaseTable(existingData, { args, toReference }) {
        return (
          existingData ||
          toReference({
            __typename: 'LogDatabaseTable',
            name: args.input.name,
            databaseName: args.input.databaseName,
          })
        );
      },
    },
  },
  Destination: {
    keyFields: ['outputId'],
  },
  AlertDetails: {
    keyFields: ['alertId'],
  },
  AlertSummary: {
    keyFields: ['alertId'],
  },
  ComplianceIntegration: {
    keyFields: ['integrationId'],
  },
  LogIntegration: {
    keyFields: ['integrationId'],
  },
  LogDatabase: {
    keyFields: ['name'],
  },
  LogDatabaseTable: {
    keyFields: ['name', 'databaseName'],
  },
  GeneralSettings: {
    keyFields: ['email'],
    fields: {
      errorReportingConsent: {
        merge(oldValue, newValue) {
          storage.write(ERROR_REPORTING_CONSENT_STORAGE_KEY, newValue);
          return newValue;
        },
      },
    },
  },
};

export default (typePolicies as unknown) as ApolloTypePolicies;
