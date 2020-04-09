/**
 * A Cloud-Native SIEM for the Modern Security Team
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
import { useGetErrorReportingConsent } from './graphql/getErrorReportingConsent.generated';

const PromptController: React.FC = () => {
  // We are intentionally over-fetching, in order to proactively add this data to the cache
  const { data } = useGetErrorReportingConsent();
  const { showModal } = useModal();

  React.useEffect(() => {
    if (data?.generalSettings.errorReportingConsent === null) {
      // Show analytics consent modal
      showModal({ modal: MODALS.ANALYTICS_CONSENT });

      // Welcome the first user while singing Katy Perry
      shootFireworks();
    }
  }, [data]);

  return null;
};

export default PromptController;
