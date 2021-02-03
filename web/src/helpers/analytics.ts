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

import { DestinationTypeEnum } from 'Generated/schema';
import storage from 'Helpers/storage';
import { pantherConfig } from 'Source/config';
import { ANALYTICS_CONSENT_STORAGE_KEY } from 'Source/constants';
import { AlertSummaryFull } from 'Source/graphql/fragments/AlertSummaryFull.generated';
import { logError } from 'Helpers/errors';

const evaluateTracking = (...args) => {
  const mixpanelPublicToken = process.env.MIXPANEL_PUBLIC_TOKEN;
  if (!mixpanelPublicToken || storage.local.read<boolean>(ANALYTICS_CONSENT_STORAGE_KEY) !== true) {
    return;
  }

  import(/* webpackChunkName: "mixpanel" */ 'mixpanel-browser').then(mx => {
    // We don't wanna initialize before any tracking occurs so we don't have to un-necessarily
    // download the mixpanel chunk at the user's device. `init` method is idempotent, meaning that
    // no matter how many times we call it, it won't override anything.
    window.requestIdleCallback(() => {
      try {
        mx.init(mixpanelPublicToken);
        const [eventName, meta] = args;
        mx.track(eventName, { ...meta, version: pantherConfig.PANTHER_VERSION });
      } catch (e) {
        // Reporting to sentry
        logError(e);
      }
    });
  });
};

export enum PageViewEnum {
  LogAnalysisOverview = 'Log Analysis Overview',
  ComplianceOverview = 'Compliance Overview',
  ListAlerts = 'List Alerts',
  ListDetections = 'List Detections',
  ListLogSources = 'List Log Sources',
  ListDataModels = 'List Data Models',
  Home = 'Home',
  Support = 'Support',
  CustomLogDetails = 'Custom Log Details Screen',
  CustomLogEditing = 'Custom Log Edit Screen',
}

interface TrackPageViewProps {
  page: PageViewEnum;
}

/* NOTE: Instead of using this directly, you MUST use the relevant hook
 * 'useTrackPageView' to avoid duplicates events
 */
export const trackPageView = ({ page }: TrackPageViewProps) => {
  evaluateTracking(page, { type: 'pageview' });
};

export enum EventEnum {
  SignedIn = 'Signed in successfully',
  AddedCustomLog = 'Added Custom Log',
  AddedDataModel = 'Added Data Model',
  UpdatedDataModel = 'Updated Data Model',
  DeletedCustomLog = 'Deleted Custom Log',
  DeletedDataModel = 'Deleted Data Model',
  UpdatedCustomLog = 'Update Custom Log',
  AddedRule = 'Added Rule',
  AddedPolicy = 'Added Policy',
  AddedComplianceSource = 'Added Compliance Source',
  AddedLogSource = 'Added Log Source',
  AddedDestination = 'Added Destination',
  PickedDestination = 'Picked Destination to create',
  PickedLogSource = 'Picked Log Source to created',
  InvitedUser = 'Invited user',
  UpdatedAlertStatus = 'Updated Alert Status',
  UpdatedComplianceSource = 'Updated Compliance Source',
  UpdatedLogSource = 'Updated Log Source',
  BulkUpdatedAlertStatus = 'Bulk Updated Alert Status',
  TestedDestination = 'Tested a destination',
  TestedDestinationSuccessfully = 'Successfully tested Destination',
  TestedDestinationFailure = 'Failed Destination test',
}

export enum SrcEnum {
  Destinations = 'destinations',
  Rules = 'rules',
  Policies = 'policies',
  Auth = 'auth',
  Users = 'users',
  Alerts = 'alerts',
  ComplianceSources = 'compliance sources',
  LogSources = 'log sources',
  CustomLogs = 'custom logs',
  DataModels = 'data models',
}

type LogSources = 'S3' | 'SQS';

interface SignInEvent {
  event: EventEnum.SignedIn;
  src: SrcEnum.Auth;
}

interface AddedCustomLogEvent {
  event: EventEnum.AddedCustomLog;
  src: SrcEnum.CustomLogs;
}

interface AddedDataModelEvent {
  event: EventEnum.AddedDataModel;
  src: SrcEnum.DataModels;
}
interface UpdatedCustomLogEvent {
  event: EventEnum.UpdatedCustomLog;
  src: SrcEnum.CustomLogs;
}

interface UpdatedDataModelEvent {
  event: EventEnum.UpdatedDataModel;
  src: SrcEnum.DataModels;
}

interface DeleteDataModelEvent {
  event: EventEnum.DeletedDataModel;
  src: SrcEnum.DataModels;
}

interface DeletedCustomLogEvent {
  event: EventEnum.DeletedCustomLog;
  src: SrcEnum.CustomLogs;
}

interface AddedRuleEvent {
  event: EventEnum.AddedRule;
  src: SrcEnum.Rules;
}

interface AddedPolicyEvent {
  event: EventEnum.AddedPolicy;
  src: SrcEnum.Policies;
}

interface DestinationEvent {
  event:
    | EventEnum.AddedDestination
    | EventEnum.PickedDestination
    | EventEnum.TestedDestination
    | EventEnum.TestedDestinationSuccessfully
    | EventEnum.TestedDestinationFailure;
  src: SrcEnum.Destinations;
  ctx: DestinationTypeEnum;
}
interface AddedDestinationEvent extends DestinationEvent {
  event: EventEnum.AddedDestination;
}

interface PickedDestinationEvent extends DestinationEvent {
  event: EventEnum.PickedDestination;
}

interface TestedDestination extends DestinationEvent {
  event: EventEnum.TestedDestination;
}

interface TestedDestinationSuccessfully extends DestinationEvent {
  event: EventEnum.TestedDestinationSuccessfully;
}

interface TestedDestinationFailure extends DestinationEvent {
  event: EventEnum.TestedDestinationFailure;
}

interface PickedLogSourceEvent {
  event: EventEnum.PickedLogSource;
  src: SrcEnum.LogSources;
  ctx: LogSources;
}

interface AddedComplianceSourceEvent {
  event: EventEnum.AddedComplianceSource;
  src: SrcEnum.ComplianceSources;
}

interface UpdatedComplianceSourceEvent {
  event: EventEnum.UpdatedComplianceSource;
  src: SrcEnum.ComplianceSources;
}

interface AddedLogSourceEvent {
  event: EventEnum.AddedLogSource;
  src: SrcEnum.LogSources;
  ctx: LogSources;
}

interface UpdatedLogSourceEvent {
  event: EventEnum.UpdatedLogSource;
  src: SrcEnum.LogSources;
  ctx: LogSources;
}

interface InvitedUserEvent {
  event: EventEnum.InvitedUser;
  src: SrcEnum.Users;
}

interface AlertStatusEvents {
  event: EventEnum.UpdatedAlertStatus | EventEnum.BulkUpdatedAlertStatus;
  src: SrcEnum.Alerts;
  data: Pick<AlertSummaryFull, 'status' | 'severity'>;
}

interface UpdatedAlertStatus extends AlertStatusEvents {
  event: EventEnum.UpdatedAlertStatus;
}

interface BulkUpdatedAlertStatus extends AlertStatusEvents {
  event: EventEnum.BulkUpdatedAlertStatus;
}

type TrackEvent =
  | AddedDestinationEvent
  | AddedDataModelEvent
  | UpdatedDataModelEvent
  | DeleteDataModelEvent
  | SignInEvent
  | AddedRuleEvent
  | AddedPolicyEvent
  | AddedLogSourceEvent
  | AddedComplianceSourceEvent
  | UpdatedComplianceSourceEvent
  | UpdatedLogSourceEvent
  | PickedDestinationEvent
  | PickedLogSourceEvent
  | InvitedUserEvent
  | UpdatedAlertStatus
  | BulkUpdatedAlertStatus
  | AddedCustomLogEvent
  | UpdatedCustomLogEvent
  | DeletedCustomLogEvent
  | TestedDestination
  | TestedDestinationSuccessfully
  | TestedDestinationFailure;

export const trackEvent = (payload: TrackEvent) => {
  evaluateTracking(payload.event, {
    type: 'event',
    src: payload.src,
    ctx: 'ctx' in payload ? payload.ctx : undefined,
    ...('data' in payload ? payload.data : undefined),
  });
};

export enum TrackErrorEnum {
  FailedToAddDestination = 'Failed to create Destination',
  FailedToAddRule = 'Failed to create Rule',
  FailedToAddPolicy = 'Failed to create Policy',
  FailedToAddCustomLog = 'Failed to create a Custom Log',
  FailedToAddDataModel = 'Failed to create a Data Model',
  FailedToUpdateDataModel = 'Failed to update a Data Model',
  FailedToEditCustomLog = 'Failed to edit a Custom Log',
  FailedToDeleteCustomLog = 'Failed to delete a Custom Log',
  FailedToDeleteDataModel = 'Failed to delete a Data Model',
  FailedToAddLogSource = 'Failed to add log source',
  FailedToUpdateLogSource = 'Failed to update log source',
  FailedToAddComplianceSource = 'Failed to add compliance source',
  FailedToUpdateComplianceSource = 'Failed to update compliance source',
  FailedMfa = 'Failed MFA',
  FailedDestinationTest = 'Failed to sent Destination test',
}

interface DestinationError {
  event: TrackErrorEnum.FailedToAddDestination | TrackErrorEnum.FailedDestinationTest;
  src: SrcEnum.Destinations;
  ctx: DestinationTypeEnum;
}

interface AddDestinationError extends DestinationError {
  event: TrackErrorEnum.FailedToAddDestination;
}

interface TestDestinationError extends DestinationError {
  event: TrackErrorEnum.FailedDestinationTest;
}

interface UpdateLogSourceError {
  event: TrackErrorEnum.FailedToUpdateLogSource;
  src: SrcEnum.LogSources;
  ctx: LogSources;
}

interface AddComplianceSourceError {
  event: TrackErrorEnum.FailedToAddComplianceSource;
  src: SrcEnum.ComplianceSources;
}

interface AddDataModelError {
  event: TrackErrorEnum.FailedToAddDataModel;
  src: SrcEnum.DataModels;
}

interface UpdateDataModelError {
  event: TrackErrorEnum.FailedToUpdateDataModel;
  src: SrcEnum.DataModels;
}

interface DeleteDataModelError {
  event: TrackErrorEnum.FailedToDeleteDataModel;
  src: SrcEnum.DataModels;
}

interface UpdateComplianceSourceError {
  event: TrackErrorEnum.FailedToUpdateComplianceSource;
  src: SrcEnum.ComplianceSources;
}

interface AddRuleError {
  event: TrackErrorEnum.FailedToAddRule;
  src: SrcEnum.Rules;
}

interface AddPolicyError {
  event: TrackErrorEnum.FailedToAddPolicy;
  src: SrcEnum.Policies;
}

interface MfaError {
  event: TrackErrorEnum.FailedMfa;
  src: SrcEnum.Auth;
}

interface AddLogSourceError {
  event: TrackErrorEnum.FailedToAddLogSource;
  src: SrcEnum.LogSources;
  ctx: LogSources;
}

interface CustomLogError {
  event:
    | TrackErrorEnum.FailedToAddCustomLog
    | TrackErrorEnum.FailedToDeleteCustomLog
    | TrackErrorEnum.FailedToUpdateLogSource;
  src: SrcEnum.CustomLogs;
}
interface DeleteCustomLogError extends CustomLogError {
  event: TrackErrorEnum.FailedToDeleteCustomLog;
}

interface UpdateCustomLogError extends CustomLogError {
  event: TrackErrorEnum.FailedToUpdateLogSource;
}
interface AddCustomLogError extends CustomLogError {
  event: TrackErrorEnum.FailedToAddCustomLog;
}

type TrackError =
  | AddDestinationError
  | AddDataModelError
  | UpdateDataModelError
  | DeleteDataModelError
  | TestDestinationError
  | AddRuleError
  | AddPolicyError
  | MfaError
  | AddCustomLogError
  | DeleteCustomLogError
  | AddLogSourceError
  | UpdateLogSourceError
  | UpdateCustomLogError
  | AddComplianceSourceError
  | UpdateComplianceSourceError;

export const trackError = (payload: TrackError) => {
  evaluateTracking(payload.event, {
    type: 'error',
    src: payload.src,
    ctx: 'ctx' in payload ? payload.ctx : undefined,
  });
};
