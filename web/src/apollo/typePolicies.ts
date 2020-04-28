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
  GeneralSettings: {
    keyFields: ['email'],
    fields: {
      errorReportingConsent: {
        merge(oldValue, newValue) {
          storage.local.write(ERROR_REPORTING_CONSENT_STORAGE_KEY, newValue);
          return newValue;
        },
      },
    },
  },
};

export default (typePolicies as unknown) as ApolloTypePolicies;
