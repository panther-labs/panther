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

import { fireEvent, render, waitMs } from 'test-utils';
import React from 'react';
import { Button } from 'pouncejs';
import mixpanel from 'mixpanel-browser';
import * as Sentry from '@sentry/browser';
import { pantherConfig } from 'Source/config';
import {
  ANALYTICS_CONSENT_STORAGE_KEY,
  ERROR_REPORTING_CONSENT_STORAGE_KEY,
} from 'Source/constants';
import {
  EventEnum,
  PageViewEnum,
  SrcEnum,
  trackError,
  TrackErrorEnum,
  trackEvent,
} from 'Helpers/analytics';
import useTrackPageView from 'Hooks/useTrackPageView';

interface TestProps {
  onClick: () => void;
}

const TestComponent: React.FC<TestProps> = ({ onClick }) => {
  useTrackPageView(PageViewEnum.LogAnalysisOverview);
  return <Button onClick={onClick}>Button click</Button>;
};

describe('Mixpanel Reporting', () => {
  describe('test with enabled analytics', () => {
    it('should report data', async () => {
      const onClick = () => {
        trackEvent({ event: EventEnum.SignedIn, src: SrcEnum.Auth });
        trackError({ event: TrackErrorEnum.FailedMfa, src: SrcEnum.Auth });
      };
      const { getByText } = render(<TestComponent onClick={() => onClick()} />);
      await waitMs(1);
      expect(mixpanel.track).toHaveBeenCalledWith(PageViewEnum.LogAnalysisOverview, {
        type: 'pageview',
        version: pantherConfig.PANTHER_VERSION,
      });
      const btn = getByText('Button click');

      fireEvent.click(btn);
      await waitMs(1);
      expect(localStorage.getItem(ANALYTICS_CONSENT_STORAGE_KEY)).toBeTruthy();
      expect(mixpanel.init).toHaveBeenCalledTimes(3);

      expect(mixpanel.track).toHaveBeenCalledTimes(3);
      expect(mixpanel.track).toHaveBeenNthCalledWith(2, EventEnum.SignedIn, {
        type: 'event',
        src: SrcEnum.Auth,
        version: pantherConfig.PANTHER_VERSION,
      });
      expect(mixpanel.track).toHaveBeenNthCalledWith(3, TrackErrorEnum.FailedMfa, {
        type: 'error',
        src: SrcEnum.Auth,
        version: pantherConfig.PANTHER_VERSION,
      });
    });

    it('should report error on Sentry when mx throws', async () => {
      const mxError = Error('Mixpanel error');
      mixpanel.init.mockImplementationOnce(() => {
        throw mxError;
      });
      render(<TestComponent onClick={() => null} />);

      await waitMs(1);
      expect(localStorage.getItem(ANALYTICS_CONSENT_STORAGE_KEY)).toBeTruthy();
      expect(localStorage.getItem(ERROR_REPORTING_CONSENT_STORAGE_KEY)).toBeTruthy();
      expect(mixpanel.track).not.toBeCalled();
      expect(Sentry.captureException).toHaveBeenCalledWith(mxError);
    });
  });
  describe('tests with disabled error reporting', () => {
    it('should NOT report error on Sentry when mx throws', async () => {
      localStorage.setItem(ERROR_REPORTING_CONSENT_STORAGE_KEY, 'false');
      const mxError = Error('Mixpanel error');
      mixpanel.init.mockImplementationOnce(() => {
        throw mxError;
      });
      render(<TestComponent onClick={() => null} />);

      await waitMs(1);
      expect(localStorage.getItem(ERROR_REPORTING_CONSENT_STORAGE_KEY)).toBeTruthy();
      expect(mixpanel.track).not.toBeCalled();
      expect(Sentry.captureException).not.toBeCalled();
    });
  });

  describe('tests with disabled analytics', () => {
    it('should NOT report data', async () => {
      localStorage.setItem(ANALYTICS_CONSENT_STORAGE_KEY, 'false');
      const onClick = () => {
        trackEvent({ event: EventEnum.SignedIn, src: SrcEnum.Auth });
        trackError({ event: TrackErrorEnum.FailedMfa, src: SrcEnum.Auth });
      };
      const { getByText } = render(<TestComponent onClick={() => onClick()} />);

      const btn = getByText('Button click');

      fireEvent.click(btn);
      await waitMs(1);
      expect(localStorage.getItem(ANALYTICS_CONSENT_STORAGE_KEY)).toBeTruthy();
      expect(mixpanel.init).not.toBeCalled();
      expect(mixpanel.track).not.toBeCalled();
    });
  });
});
