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

import React from 'react';
import useModal from 'Hooks/useModal';
import { MODALS } from 'Components/utils/Modal';
import shootFireworks from 'Helpers/fireworks';
import { useGetGeneralSettingsConsents } from './graphql/getGeneralSettingsConsents.generated';

const PromptController: React.FC = () => {
  const { showModal } = useModal();
  // We are intentionally over-fetching, in order to proactively add this data to the cache
  useGetGeneralSettingsConsents({
    onCompleted: data => {
      const shouldShowErrorConsent = data.generalSettings.errorReportingConsent === null;
      const shouldShowProductAnalyticsConsent = data.generalSettings.analyticsConsent === null;
      const shouldShowConsentModal = shouldShowErrorConsent || shouldShowProductAnalyticsConsent;
      if (shouldShowConsentModal) {
        // Show analytics consent modal
        showModal({
          modal: MODALS.ANALYTICS_CONSENT,
          props: {
            showErrorConsent: shouldShowErrorConsent,
            showProductAnalyticsConsent: shouldShowProductAnalyticsConsent,
          },
        });

        // Welcome the first user while singing Katy Perry
        if (shouldShowErrorConsent) {
          shootFireworks();
        }
      }
    },
  });

  return null;
};

export default PromptController;
