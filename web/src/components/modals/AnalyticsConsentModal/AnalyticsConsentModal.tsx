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

import React from 'react';
import { Modal, Text, Box, useSnackbar, Alert } from 'pouncejs';
import useModal from 'Hooks/useModal';
import AnalyticsConsentForm from 'Components/forms/AnalyticsConsentForm';
import { extractErrorMessage } from 'Helpers/utils';
import { useUpdateGeneralSettingsConsents } from './graphql/updateGeneralSettingsConsents.generated';

const AnalyticsConsentModal: React.FC = () => {
  const { pushSnackbar } = useSnackbar();
  const { hideModal } = useModal();
  const [saveConsentPreferences, { data, error }] = useUpdateGeneralSettingsConsents();

  React.useEffect(() => {
    if (data) {
      pushSnackbar({ variant: 'success', title: `Successfully updated your preferences` });
      hideModal();
    }
  }, [data]);

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
        {error ? (
          <Alert
            title="An error occured"
            description={extractErrorMessage(error)}
            variant="error"
          />
        ) : (
          <AnalyticsConsentForm
            onSubmit={values =>
              saveConsentPreferences({
                variables: {
                  input: values,
                },
              })
            }
          />
        )}
      </Box>
    </Modal>
  );
};

export default AnalyticsConsentModal;
