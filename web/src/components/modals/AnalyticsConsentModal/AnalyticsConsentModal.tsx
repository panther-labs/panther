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
import { Modal, Text, Box, useSnackbar } from 'pouncejs';
import useModal from 'Hooks/useModal';
import AnalyticsConsentForm from 'Components/forms/AnalyticsConsentForm';
import { extractErrorMessage } from 'Helpers/utils';
import { useUpdateGeneralSettingsConsents } from './graphql/updateGeneralSettingsConsents.generated';

const AnalyticsConsentModal: React.FC = () => {
  const { pushSnackbar } = useSnackbar();
  const { hideModal } = useModal();
  const [saveConsentPreferences] = useUpdateGeneralSettingsConsents({
    onCompleted: () => {
      hideModal();
      pushSnackbar({ variant: 'success', title: `Successfully updated your preferences` });
    },
    onError: error => {
      hideModal();
      pushSnackbar({
        variant: 'error',
        title:
          extractErrorMessage(error) ||
          'Failed to update your preferences due to an unknown and unpredicted error',
      });
    },
  });

  return (
    <Modal
      open
      disableBackdropClick
      disableEscapeKeyDown
      onClose={hideModal}
      title="Help Improve Panther!"
    >
      <Box width={600} px={100} pb={25}>
        <Text size="large" color="grey300" mb={8}>
          Opt-in to occasionally provide diagnostic information for improving reliability.
          <b> All information is anonymized.</b>
        </Text>
        <AnalyticsConsentForm
          onSubmit={values =>
            saveConsentPreferences({
              variables: {
                input: values,
              },
            })
          }
        />
      </Box>
    </Modal>
  );
};

export default AnalyticsConsentModal;
