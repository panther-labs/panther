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
import mx from 'mixpanel-browser';
import storage from 'Helpers/storage';
import { ANALYTICS_CONSENT_STORAGE_KEY } from 'Source/constants';

// TODO: Pending backend to work
const mixpanelPublicToken = process.env.MIXPANEL_PUBLIC_TOKEN;

const envCheck = mixpanelPublicToken && storage.local.read<boolean>(ANALYTICS_CONSENT_STORAGE_KEY);

const evaluateTracking = (...args) => {
  if (envCheck) {
    mx.init(mixpanelPublicToken);
    mx.track(...args);
  }
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
}

export enum SrcEnum {
  Destinations = 'destinations',
  Rules = 'rules',
  Policies = 'policies',
  Auth = 'auth',
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

interface AddedDestinationEvent {
  event: EventEnum.AddedDestination;
  src: SrcEnum.Destinations;
  ctx: DestinationTypeEnum;
}

interface PickedDestinationEvent {
  event: EventEnum.PickedDestination;
  src: SrcEnum.Destinations;
  ctx: DestinationTypeEnum;
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

type TrackEvent =
  | AddedDestinationEvent
  | SignInEvent
  | AddedRuleEvent
  | AddedPolicyEvent
  | AddedLogSourceEvent
  | PickedDestinationEvent
  | PickedLogSourceEvent;

export const trackEvent = (payload: TrackEvent) => {
  evaluateTracking(payload.event, {
    type: 'event',
    src: payload.src,
    ctx: 'ctx' in payload ? payload.ctx : null,
  });
};

export enum TrackErrorEnum {
  FailedToAddDestination = 'Failed to create Destination',
  FailedToAddRule = 'Failed to create Rule',
  FailedMfa = 'Failed MFA',
}

interface ErrorEvent {
  data: any;
}

interface AddDestinationError extends ErrorEvent {
  event: TrackErrorEnum.FailedToAddDestination;
  src: SrcEnum.Destinations;
  ctx: DestinationTypeEnum;
}

interface AddRuleError extends ErrorEvent {
  event: TrackErrorEnum.FailedToAddRule;
  src: SrcEnum.Rules;
}
interface MfaError extends ErrorEvent {
  event: TrackErrorEnum.FailedMfa;
  src: SrcEnum.Auth;
}

type TrackError = AddDestinationError | AddRuleError | MfaError;

export const trackError = (payload: TrackError) => {
  evaluateTracking(payload.event, {
    type: 'error',
    src: payload.src,
    ctx: 'ctx' in payload ? payload.ctx : null,
    data: 'data' in payload ? payload.data : null,
  });
};
