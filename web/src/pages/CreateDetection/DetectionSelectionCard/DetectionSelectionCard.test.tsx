import React from 'react';
import { render } from 'test-utils';
import DetectionSelectionCard from './DetectionSelectionCard';

describe('DetectionSelectionCard', () => {
  it('matches snapshot', () => {
    const { container } = render(
      <React.Fragment>
        <DetectionSelectionCard
          title="Rule"
          description="Fake Description"
          icon="add"
          iconColor="red-100"
        />

        <DetectionSelectionCard
          title="Scheduled Rule"
          description="Fake Description"
          icon="user"
          iconColor="green-100"
          availableInEnterprise
        />
      </React.Fragment>
    );

    expect(container).toMatchSnapshot();
  });

  it('shows the necessary info', () => {
    const { getByText, getByAriaLabel } = render(
      <DetectionSelectionCard
        title="Rule"
        description="Fake Description"
        icon="add"
        iconColor="red-100"
      />
    );

    expect(getByAriaLabel('Create Rule')).toBeInTheDocument();
    expect(getByText('Rule')).toBeInTheDocument();
    expect(getByText('Fake Description')).toBeInTheDocument();
  });
});
