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
import { Form, Formik, FastField } from 'formik';
import { Box, Flex, Text } from 'pouncejs';
import { AlertStatusesEnum } from 'Generated/schema';
import FormikCombobox from 'Components/fields/ComboBox';
import { capitalize } from 'Helpers/utils';
import SubmitButton from 'Components/buttons/SubmitButton';
import { useSelect } from 'Components/utils/SelectContext';

const initialValues = {
  status: AlertStatusesEnum.Resolved,
};
const statusOptions = Object.values(AlertStatusesEnum);

const filterItemToString = (item: AlertStatusesEnum) => capitalize(item.toLowerCase());

interface ListAlertSelectionFormValues {
  status: string;
}

const ListAlertSelection: React.FC = () => {
  const { selection } = useSelect();
  return (
    <Flex justify="flex-end" align="center">
      <Formik<ListAlertSelectionFormValues>
        initialValues={initialValues}
        onSubmit={
          // TODO: Make this functional
          // eslint-disable-next-line @typescript-eslint/no-unused-vars
          (values: ListAlertSelectionFormValues) => {
            // @ts-ignore
            // eslint-disable-next-line no-console
            console.log('values');
          }
        }
      >
        <Form>
          <Flex spacing={4} align="center">
            <Text>{selection.length} Selected</Text>
            <Box width={150}>
              <FastField
                name="status"
                as={FormikCombobox}
                items={statusOptions}
                itemToString={filterItemToString}
                label="Status"
                placeholder="Select statuses"
              />
            </Box>
            <SubmitButton allowPristineSubmission>Apply</SubmitButton>
          </Flex>
        </Form>
      </Formik>
    </Flex>
  );
};

export default React.memo(ListAlertSelection);
