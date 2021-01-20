import React from 'react';
import { fireEvent, render } from 'test-utils';
import CreateDetection from './CreateDetection';

describe('CreateDetection', () => {
  it('allows toggling between policy & rule forms', async () => {
    const { queryByAriaLabel, queryByLabelText } = render(<CreateDetection />);

    expect(queryByLabelText('Rule ID')).toBeInTheDocument();
    expect(queryByLabelText('Policy ID')).not.toBeInTheDocument();

    fireEvent.click(queryByAriaLabel('Create Policy'));

    expect(queryByLabelText('Policy ID')).toBeInTheDocument();
    expect(queryByLabelText('Rule ID')).not.toBeInTheDocument();

    fireEvent.click(queryByAriaLabel('Create Rule'));

    expect(queryByLabelText('Policy ID')).not.toBeInTheDocument();
    expect(queryByLabelText('Rule ID')).toBeInTheDocument();

    expect(queryByAriaLabel('Create Scheduled Rule')).not.toBeInTheDocument();
  });
});
