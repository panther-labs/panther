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
import { Button, ButtonProps } from 'pouncejs';
import { useFormikContext } from 'formik';

export interface SubmitButtonProps extends Omit<ButtonProps, 'size' | 'disabled'> {
  allowPristineSubmission?: boolean;
  allowInvalidSubmission?: boolean;
}

const SubmitButton: React.FC<SubmitButtonProps> = ({
  allowPristineSubmission,
  allowInvalidSubmission,
  ...rest
}) => {
  const { isSubmitting, isValid, dirty, submitForm } = useFormikContext<any>();
  return (
    <Button
      type="submit"
      onClick={e => {
        // We force a submission instead of relying in native HTML (from `type="submit"`), in order
        // to cover cases of a remote form submission
        e.preventDefault();
        submitForm();
      }}
      loading={isSubmitting}
      disabled={
        isSubmitting ||
        (!isValid && !allowInvalidSubmission) ||
        (!dirty && !allowPristineSubmission)
      }
      {...rest}
    />
  );
};

export default React.memo(SubmitButton);
