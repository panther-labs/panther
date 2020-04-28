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
import { Formik } from 'formik';
import SubmitButton from 'Components/buttons/SubmitButton';
import * as Yup from 'yup';
import { Flex, Button } from 'pouncejs';
import useRouter from 'Hooks/useRouter';

interface IdValue {
  id: string;
}

export interface BaseRuleFormProps<BaseRuleFormValues extends IdValue> {
  /** The initial values of the form */
  initialValues: BaseRuleFormValues;

  /** callback for the submission of the form */
  onSubmit: (values: BaseRuleFormValues) => void;

  /** The validation schema that the form will have */
  validationSchema: Yup.ObjectSchema<Yup.Shape<object, Partial<BaseRuleFormValues> & IdValue>>;
}

function BaseRuleForm<BaseRuleFormValues extends IdValue>({
  initialValues,
  onSubmit,
  validationSchema,
  children,
}: React.PropsWithChildren<BaseRuleFormProps<BaseRuleFormValues>>): React.ReactElement<
  BaseRuleFormProps<BaseRuleFormValues>
> {
  const { history } = useRouter();

  return (
    <Formik<BaseRuleFormValues>
      initialValues={initialValues}
      onSubmit={onSubmit}
      enableReinitialize
      validationSchema={validationSchema}
    >
      {({ handleSubmit, isSubmitting, isValid, dirty }) => {
        return (
          <form onSubmit={handleSubmit}>
            {children}
            <Flex borderTop="1px solid" borderColor="grey100" pt={6} mt={10} justify="flex-end">
              <Flex>
                <Button variant="default" size="large" onClick={history.goBack} mr={4}>
                  Cancel
                </Button>
                <SubmitButton
                  submitting={isSubmitting}
                  disabled={!dirty || !isValid || isSubmitting}
                >
                  {initialValues.id ? 'Update' : 'Create'}
                </SubmitButton>
              </Flex>
            </Flex>
          </form>
        );
      }}
    </Formik>
  );
}

export default BaseRuleForm;
