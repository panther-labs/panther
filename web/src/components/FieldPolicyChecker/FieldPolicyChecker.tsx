import React from 'react';
import { Flex } from 'pouncejs';
import FieldPolicyCheck from './FieldPolicyCheck';

interface FieldPolicyCheckerProps {
  value: string;
  schema: any;
}

const FieldPolicyChecker: React.FC<FieldPolicyCheckerProps> = ({ schema, value }) => {
  const [policyErrors, setPolicyErrors] = React.useState([]);

  // Normally you would expect that we can just read the errors from Formik,  but Formik only
  // keeps the first failing error for a field. Thus, we can't know how many checks  are failing
  // and how many are passing. To combat that we have to implement our own "error storing" logic
  // in which we save ALL the errors for a field
  // https://github.com/formium/formik/issues/243#issue-272680265
  React.useEffect(() => {
    schema
      .validate(value, { abortEarly: false })
      .then(() => setPolicyErrors([]))
      .catch(err => setPolicyErrors(err.errors));
  }, [value, schema, setPolicyErrors]);

  return (
    <Flex direction="column" spacing={3}>
      {schema.tests.map(test => {
        const { message, name } = test.OPTIONS;

        // The "field is required" check doesn't have a reason to be listed to the users as a
        // visible "check" that they must pass, since it doesn't make sense
        if (name === 'required') {
          return null;
        }

        return (
          <FieldPolicyCheck key={message} passing={!policyErrors.includes(message)}>
            {message}
          </FieldPolicyCheck>
        );
      })}
    </Flex>
  );
};

export default React.memo(FieldPolicyChecker);
