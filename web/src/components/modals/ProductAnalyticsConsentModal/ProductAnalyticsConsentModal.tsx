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
import { Modal, Text, Box, useSnackbar, Alert, ModalProps } from 'pouncejs';
import ProductAnalyticsConsentForm from 'Components/forms/ProductAnalyticsConsentForm';
import { extractErrorMessage } from 'Helpers/utils';
import { useUpdateGeneralSettingsConsents } from '../AnalyticsConsentModal/graphql/updateGeneralSettingsConsents.generated';

const ProductAnalyticsConsentModal: React.FC<ModalProps> = ({ onClose, ...rest }) => {
  const { pushSnackbar } = useSnackbar();
  const [
    saveConsentPreferences,
    { error: updateGeneralPreferencesError },
  ] = useUpdateGeneralSettingsConsents({
    onCompleted: () => {
      onClose();
      pushSnackbar({ variant: 'success', title: `Successfully updated your preferences` });
    },
    onError: error => {
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
      onClose={() => {}}
      title="Help us improve Panther!"
      aria-describedby="modal-subtitle"
      {...rest}
    >
      <Box width={500} px={10}>
        <Text fontSize="medium" mb={8} id="modal-subtitle">
          There a couple of things that need your review before continuing.
        </Text>
        {updateGeneralPreferencesError ? (
          <Alert
            title="An error occurred"
            description={extractErrorMessage(updateGeneralPreferencesError)}
            variant="error"
          />
        ) : (
          <ProductAnalyticsConsentForm
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

export default ProductAnalyticsConsentModal;
