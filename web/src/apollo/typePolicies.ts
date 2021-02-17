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

import { Query, ResolversParentTypes } from 'Generated/schema';
import storage from 'Helpers/storage';
import { ERROR_REPORTING_CONSENT_STORAGE_KEY, ANALYTICS_CONSENT_STORAGE_KEY } from 'Source/constants'; // prettier-ignore
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
      destination(existing, { args, toReference }) {
        return existing || toReference({ __typename: 'Destination', outputId: args.id });
      },
      getComplianceIntegration(existing, { args, toReference }) {
        return (
          existing || toReference({ __typename: 'ComplianceIntegration', integrationId: args.id })
        );
      },
      getDataModel(existing, { args, toReference }) {
        return existing || toReference({ __typename: 'DataModel', id: args.id });
      },
      getAnalysisPack(existing, { args, toReference }) {
        return existing || toReference({ __typename: 'AnalysisPack', id: args.id });
      },
      getS3LogIntegration(existing, { args, toReference }) {
        return existing || toReference({ __typename: 'S3LogIntegration', integrationId: args.id });
      },
      getSqsLogIntegration(existingData, { args, toReference }) {
        return (
          existingData ||
          toReference({ __typename: 'SqsLogSourceIntegration', integrationId: args.id })
        );
      },
      // TODO: when apollo client is updated to 3.0.0-rc.12+, use this code
      // // For GetAlert (AlertDetails)
      // alert: {
      //   read(existing) {
      //     return existing;
      //   },
      //   merge(existing, incoming, { mergeObjects }) {
      //     return mergeObjects(existing, incoming);
      //   },
      // },
      // // For ListAlerts (ListAlertsReponse)
      // alerts: {
      //   read(existing) {
      //     return existing;
      //   },
      //   merge(existing, incoming, { mergeObjects }) {
      //     return mergeObjects(existing, incoming);
      //   },
      // },
    },
  },
  Destination: {
    keyFields: ['outputId'],
  },
  AlertDetails: {
    keyFields: ['alertId'],
    // TODO: when apollo client is updated to 3.0.0-rc.12+, use this code
    // fields: {
    //   events: {
    //     merge(_, incoming) {
    //       return incoming;
    //     },
    //   },
    //   status: {
    //     merge(_, incoming) {
    //       return incoming;
    //     },
    //   },
    // },
  },
  AlertSummary: {
    keyFields: ['alertId'],
    // TODO: when apollo client is updated to 3.0.0-rc.12+, use this code
    // fields: {
    //   status: {
    //     merge(_, incoming) {
    //       return incoming;
    //     },
    //   },
    // },
  },
  CustomLogRecord: {
    keyFields: ['logType'],
  },
  ComplianceIntegration: {
    keyFields: ['integrationId'],
  },
  S3LogIntegration: {
    keyFields: ['integrationId'],
  },
  SqsLogSourceIntegration: {
    keyFields: ['integrationId'],
  },
  GeneralSettings: {
    keyFields: ['__typename'],
    fields: {
      errorReportingConsent: {
        merge(_, incoming) {
          storage.local.write(ERROR_REPORTING_CONSENT_STORAGE_KEY, incoming);
          return incoming;
        },
      },
      analyticsConsent: {
        merge(_, incoming) {
          storage.local.write(ANALYTICS_CONSENT_STORAGE_KEY, incoming);
          return incoming;
        },
      },
    },
  },
};

export default (typePolicies as unknown) as ApolloTypePolicies;
