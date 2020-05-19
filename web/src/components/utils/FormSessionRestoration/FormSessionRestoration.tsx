import React from 'react';
import useFormSessionRestoration, {
  UseFormSessionRestorationProps,
} from 'Hooks/useFormSessionRestoration';

type FormSessionRestorationProps = UseFormSessionRestorationProps;

const FormSessionRestoration: React.FC<FormSessionRestorationProps> = ({ children, ...rest }) => {
  useFormSessionRestoration(rest);

  return children as React.ReactElement;
};

export default FormSessionRestoration;
