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
import { ButtonProps } from 'pouncejs';
import { useFormikContext } from 'formik';
import LoadingButton from 'Components/buttons/LoadingButton';

interface SubmitButtonProps extends Omit<ButtonProps, 'size' | 'variant' | 'disabled'> {
  allowPristineSubmission?: boolean;
}

const SubmitButton: React.FC<SubmitButtonProps> = ({ allowPristineSubmission, ...rest }) => {
  const { isSubmitting, isValid, dirty } = useFormikContext<any>();

  return (
    <LoadingButton
      {...rest}
      loading={isSubmitting}
      disabled={isSubmitting || !isValid || (!dirty && !allowPristineSubmission)}
    />
  );
};

export default React.memo(SubmitButton);
