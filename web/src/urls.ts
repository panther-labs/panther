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

import {
  AlertDetails,
  ComplianceIntegration,
  Destination,
  GlobalPythonModule,
  LogIntegration,
  Policy,
  ResourceDetails,
  Rule,
  CustomLogRecord,
  DataModel,
  Pack,
} from 'Generated/schema';

// Typical URL encoding, allowing colons (:) to be present in the URL. Colons are safe.
// https://stackoverflow.com/questions/14872629/uriencode-and-colon
const urlEncode = (str: string) => encodeURIComponent(str).replace(/%3A/g, unescape);

const urls = {
  detections: {
    home: () => '/detections/',
    list: () => urls.detections.home(),
    create: () => `${urls.detections.home()}new/`,
  },
  compliance: {
    home: () => '/cloud-security/',
    overview: () => `${urls.compliance.home()}overview/`,
    policies: {
      list: () => `${urls.detections.list()}policies/`,
      create: () => `${urls.detections.create()}?type=policy`,
      details: (id: Policy['id']) => `${urls.compliance.policies.list()}${urlEncode(id)}/`,
      edit: (id: Policy['id']) => `${urls.compliance.policies.details(id)}edit/`,
    },
    resources: {
      list: () => `${urls.compliance.home()}resources/`,
      details: (id: ResourceDetails['id']) => `${urls.compliance.resources.list()}${urlEncode(id)}/`, // prettier-ignore
      edit: (id: ResourceDetails['id']) => `${urls.compliance.resources.details(id)}edit/`,
    },
    sources: {
      list: () => `${urls.compliance.home()}sources/`,
      create: () => `${urls.compliance.sources.list()}new/`,
      edit: (id: ComplianceIntegration['integrationId']) =>
        `${urls.compliance.sources.list()}${id}/edit/`,
    },
  },
  logAnalysis: {
    home: () => '/log-analysis/',
    overview: () => `${urls.logAnalysis.home()}overview/`,
    dataModels: {
      list: () => `${urls.logAnalysis.home()}data-models/`,
      create: () => `${urls.logAnalysis.dataModels.list()}new/`,
      details: (id: DataModel['id']) => `${urls.logAnalysis.dataModels.list()}${urlEncode(id)}/`,
      edit: (id: DataModel['id']) => `${urls.logAnalysis.dataModels.details(id)}edit/`,
    },
    rules: {
      list: () => `${urls.detections.list()}rules/`,
      create: () => `${urls.detections.create()}?type=rule`,
      details: (id: Rule['id']) => `${urls.logAnalysis.rules.list()}${urlEncode(id)}/`,
      edit: (id: Rule['id']) => `${urls.logAnalysis.rules.details(id)}edit/`,
    },
    alerts: {
      list: () => `${urls.logAnalysis.home()}alerts/`,
      details: (id: AlertDetails['alertId']) => `${urls.logAnalysis.alerts.list()}${urlEncode(id)}/` // prettier-ignore
    },
    sources: {
      list: () => `${urls.logAnalysis.home()}sources/`,
      create: (type?: string) => `${urls.logAnalysis.sources.list()}new/${type || ''}`,
      edit: (id: LogIntegration['integrationId'], type: string) =>
        `${urls.logAnalysis.sources.list()}${type}/${id}/edit/`,
    },
    customLogs: {
      list: () => `${urls.logAnalysis.home()}custom-logs/`,
      details: (logType: CustomLogRecord['logType']) =>
        `${urls.logAnalysis.customLogs.list()}${urlEncode(logType)}/`,
      edit: (logType: CustomLogRecord['logType']) =>
        `${urls.logAnalysis.customLogs.details(logType)}/edit/`,
      create: () => `${urls.logAnalysis.customLogs.list()}new/`,
    },
  },
  packs: {
    home: () => '/packs/',
    list: () => urls.packs.home(),
    details: (id: Pack['id']) => `${urls.packs.home()}${urlEncode(id)}/`,
  },
  settings: {
    home: () => '/settings/',
    general: () => `${urls.settings.home()}general/`,
    globalPythonModules: {
      list: () => `${urls.settings.home()}global-python-modules/`,
      create: () => `${urls.settings.globalPythonModules.list()}new/`,
      edit: (id: GlobalPythonModule['id']) =>
        `${urls.settings.globalPythonModules.list()}${urlEncode(id)}/edit/`,
    },
    bulkUploader: () => `${urls.settings.home()}bulk-uploader/`,
    users: () => `${urls.settings.home()}users/`,
    destinations: {
      list: () => `${urls.settings.home()}destinations/`,
      create: () => `${urls.settings.destinations.list()}new/`,
      edit: (id: Destination['outputId']) =>
        `${urls.settings.destinations.list()}${urlEncode(id)}/edit/`,
    },
  },
  account: {
    auth: {
      signIn: () => `/sign-in/`,
      forgotPassword: () => `/password-forgot/`,
      resetPassword: () => `/password-reset/`,
    },
    support: () => '/support',
  },
};

export default urls;
