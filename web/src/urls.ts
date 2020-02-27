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

import { AlertDetails, PolicyDetails, ResourceDetails, RuleDetails } from 'Generated/schema';

// Typical URL encoding, allowing colons (:) to be present in the URL. Colons are safe.
// https://stackoverflow.com/questions/14872629/uriencode-and-colon
const urlEncode = (str: string) => encodeURIComponent(str).replace(/%3A/g, unescape);

const urls = {
  compliance: {
    home: () => '/cloud-security/',
    overview: () => `${urls.compliance.home()}overview/`,
    policies: {
      list: () => `${urls.compliance.home()}policies/`,
      create: () => `${urls.compliance.policies.list()}new/`,
      details: (id: PolicyDetails['id']) => `${urls.compliance.policies.list()}${urlEncode(id)}/`,
      edit: (id: PolicyDetails['id']) => `${urls.compliance.policies.details(id)}edit/`,
    },
    resources: {
      list: () => `${urls.compliance.home()}resources/`,
      details: (id: ResourceDetails['id']) => `${urls.compliance.resources.list()}${urlEncode(id)}/`, // prettier-ignore
      edit: (id: ResourceDetails['id']) => `${urls.compliance.resources.details(id)}edit/`,
    },
    sources: {
      list: () => `${urls.compliance.home()}sources/`,
      create: () => `${urls.compliance.sources.list()}new/`,
    },
  },
  logAnalysis: {
    home: () => '/log-analysis/',
    overview: () => `${urls.logAnalysis.home()}overview/`,
    rules: {
      list: () => `${urls.logAnalysis.home()}rules/`,
      create: () => `${urls.logAnalysis.rules.list()}new/`,
      details: (id: RuleDetails['id']) => `${urls.logAnalysis.rules.list()}${urlEncode(id)}/`,
      edit: (id: RuleDetails['id']) => `${urls.logAnalysis.rules.details(id)}edit/`,
    },
    alerts: {
      list: () => `${urls.logAnalysis.home()}alerts/`,
      details: (id: AlertDetails['alertId']) => `${urls.logAnalysis.alerts.list()}${urlEncode(id)}/` // prettier-ignore
    },
    sources: {
      list: () => `${urls.logAnalysis.home()}sources/`,
      create: () => `${urls.logAnalysis.sources.list()}new/`,
    },
  },
  settings: {
    overview: () => `/settings/`,
    general: () => `${urls.settings.overview()}general`,
    users: () => `${urls.settings.overview()}users`,
    destinations: () => `${urls.settings.overview()}destinations`,
  },
  account: {
    auth: {
      signIn: () => `/sign-in/`,
      forgotPassword: () => `/password-forgot/`,
      resetPassword: () => `/password-reset/`,
    },
  },
};

export default urls;
