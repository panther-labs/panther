/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

import { AlertSummary, PolicySummary, ResourceSummary, RuleSummary } from 'Generated/schema';
import { INTEGRATION_TYPES } from 'Source/constants';

const urls = {
  overview: () => '/overview',
  rules: {
    list: () => '/rules/',
    details: (id: RuleSummary['id']) => `${urls.rules.list()}${encodeURIComponent(id)}/`,
    edit: (id: RuleSummary['id']) => `${urls.rules.details(id)}edit/`,
    create: () => `${urls.rules.list()}new/`,
  },
  policies: {
    list: () => '/policies/',
    details: (id: PolicySummary['id']) => `${urls.policies.list()}${encodeURIComponent(id)}/`,
    edit: (id: PolicySummary['id']) => `${urls.policies.details(id)}edit/`,
    create: () => `${urls.policies.list()}new/`,
  },
  resources: {
    list: () => '/resources/',
    details: (id: ResourceSummary['id']) => `${urls.resources.list()}${encodeURIComponent(id)}/`,
    edit: (id: ResourceSummary['id']) => `${urls.resources.details(id)}edit/`,
  },
  alerts: {
    list: () => '/alerts/',
    details: (id: AlertSummary['alertId']) => `${urls.alerts.list()}${encodeURIComponent(id)}/`,
  },
  account: {
    settings: {
      overview: () => `/settings/`,
      general: () => `${urls.account.settings.overview()}general`,
      users: () => `${urls.account.settings.overview()}users`,
      sources: {
        list: () => `${urls.account.settings.overview()}sources/`,
        create: (integrationType?: INTEGRATION_TYPES) =>
          `${urls.account.settings.sources.list()}new/${
            integrationType ? `?type=${integrationType}` : ''
          }`,
      },
      destinations: () => `${urls.account.settings.overview()}destinations`,
    },

    auth: {
      signIn: () => `/sign-in/`,
      forgotPassword: () => `/password-forgot/`,
      resetPassword: () => `/password-reset/`,
    },
  },

  integrations: {
    details: (serviceName: string) => `/integrations/${serviceName}`,
  },
};

export default urls;
