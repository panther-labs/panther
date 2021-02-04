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
import semver from 'semver';
import { Pack } from 'Generated/schema';
import { Button, Flex, Box } from 'pouncejs';
import { Form, Formik, FastField } from 'formik';
import FormikCombobox from 'Components/fields/ComboBox';

interface UpdateVersionProps {
  pack: Pick<Pack, 'availableVersions' | 'packVersion' | 'enabled'>;
  onPatch: (values: UpdateVersionFormValues) => void;
}

export interface UpdateVersionFormValues {
  packVersion: {
    id: string;
    name: string;
  };
}
const UpdateVersion: React.FC<UpdateVersionProps> = ({
  pack: { enabled, availableVersions, packVersion: current },
  onPatch,
}) => {
  availableVersions.sort((a, b) => semver.rcompare(a.name, b.name));

  const initialValues = { packVersion: availableVersions[0] };
  return (
    <Formik<UpdateVersionFormValues> initialValues={initialValues} onSubmit={onPatch}>
      {({ values }) => {
        return (
          <Form>
            <Flex spacing={4}>
              <Box width={100}>
                <FastField
                  name="packVersion"
                  as={FormikCombobox}
                  disabled={!enabled}
                  items={availableVersions}
                  itemToString={v => v.name}
                />
              </Box>
              <Box width={130}>
                {semver.lt(values.packVersion.name, current.name) ? (
                  <Button type="submit" fullWidth variantColor="violet" disabled={!enabled}>
                    Roll Back
                  </Button>
                ) : (
                  <Button
                    type="submit"
                    fullWidth
                    disabled={!enabled || values.packVersion.name === current.name}
                  >
                    Update Pack
                  </Button>
                )}
              </Box>
            </Flex>
          </Form>
        );
      }}
    </Formik>
  );
};

export default React.memo(UpdateVersion);
