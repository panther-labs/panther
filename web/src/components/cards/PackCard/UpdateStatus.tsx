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
import { Pack } from 'Generated/schema';
import { Form, Formik, FastField } from 'formik';
import FormikSwitch from 'Components/fields/Switch';
import FormikAutosave from 'Components/utils/Autosave';

interface UpdateStatusProps {
  pack: Pick<Pack, 'enabled'>;
  onUpdate: (values: UpdateStatusFormValues) => void;
}

export interface UpdateStatusFormValues {
  enabled: boolean;
}
const UpdateStatus: React.FC<UpdateStatusProps> = ({ pack: { enabled }, onUpdate }) => {
  const initialValues = React.useMemo(() => ({ enabled }), [enabled]);
  return (
    <Formik<UpdateStatusFormValues>
      enableReinitialize
      initialValues={initialValues}
      onSubmit={onUpdate}
    >
      <Form>
        <FormikAutosave />
        <FastField as={FormikSwitch} name="enabled" label="Enabled" placeholder="Toggle Enabled" />
      </Form>
    </Formik>
  );
};

export default React.memo(UpdateStatus);
