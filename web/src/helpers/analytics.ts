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
import { ANALYTICS_CONSENT_STORAGE_KEY, STABLE_PANTHER_VERSION } from 'Source/constants';
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
        mx.track(eventName, { ...meta, version: STABLE_PANTHER_VERSION });
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
  ListRules = 'List Rules',
  ListAlerts = 'List Alerts',
  ListLogSources = 'List Log Sources',
  Home = 'Home',
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
  AddedRule = 'Added Rule',
  AddedPolicy = 'Added Policy',
  AddedLogSource = 'Added Log Source',
  AddedDestination = 'Added Destination',
  PickedDestination = 'Picked Destination to create',
  PickedLogSource = 'Picked Log Source to created',
  InvitedUser = 'Invited user',
  UpdatedAlertStatus = 'Updated Alert Status',
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
  LogSources = 'log sources',
}

type LogSources = 'S3' | 'SQS';

interface SignInEvent {
  event: EventEnum.SignedIn;
  src: SrcEnum.Auth;
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

interface AddedLogSourceEvent {
  event: EventEnum.AddedLogSource;
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
  | SignInEvent
  | AddedRuleEvent
  | AddedPolicyEvent
  | AddedLogSourceEvent
  | PickedDestinationEvent
  | PickedLogSourceEvent
  | InvitedUserEvent
  | UpdatedAlertStatus
  | BulkUpdatedAlertStatus
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

interface AddRuleError {
  event: TrackErrorEnum.FailedToAddRule;
  src: SrcEnum.Rules;
}
interface MfaError {
  event: TrackErrorEnum.FailedMfa;
  src: SrcEnum.Auth;
}

type TrackError = AddDestinationError | TestDestinationError | AddRuleError | MfaError;

export const trackError = (payload: TrackError) => {
  evaluateTracking(payload.event, {
    type: 'error',
    src: payload.src,
    ctx: 'ctx' in payload ? payload.ctx : undefined,
  });
};
