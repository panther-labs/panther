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

const envCheck =
  mixpanelPublicToken &&
  // TODO: Pending backend to work
  storage.local.read<boolean>(ANALYTICS_CONSENT_STORAGE_KEY) &&
  process.env.NODE_ENV === 'production';

const evaluateTracking = (...args) => {
  if (envCheck) {
    mx.init(mixpanelPublicToken);
    mx.track(...args);
  }
};

enum TrackEventEnum {
  'picked-destination-to-create' = 'Picked Destination to create',
  'added-destination' = 'Added Destination',
  'added-rule' = 'Added Rule',
  'success-sign-in' = 'Successful Sign in',
}

enum TrackErrorEnum {
  'failed-to-add-destination' = 'Failed to create destination',
  'failed-to-create-rule' = 'Failed to create Rule',
  'failed-mfa' = 'Failed MFA',
}

enum TrackPageViewEnum {
  'log-analysis-overview' = 'Log Analysis Overview',
}

type srcType = 'destinations';
type ctxType = DestinationTypeEnum;

interface TrackPageViewProps {
  page: keyof typeof TrackPageViewEnum;
}

interface TrackEventProps {
  event: keyof typeof TrackEventEnum;
  src?: srcType;
  ctx?: ctxType;
}

interface TrackErrorProps {
  error: keyof typeof TrackErrorEnum;
  src?: srcType;
  ctx?: ctxType;
  data?: any;
}

export const trackPageView = ({ page }: TrackPageViewProps) => {
  evaluateTracking(TrackPageViewEnum[page], { type: 'pageview' });
};

export const trackEvent = ({ event, src, ctx }: TrackEventProps) => {
  evaluateTracking(TrackEventEnum[event], { type: 'event', src, ctx });
};

export const trackError = ({ error, src, ctx, data }: TrackErrorProps) => {
  evaluateTracking(TrackErrorEnum[error], { type: 'error', src, ctx, data });
};
