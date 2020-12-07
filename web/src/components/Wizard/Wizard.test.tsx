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
import { render, fireEvent } from 'test-utils';
import { useWizardContext, Wizard, WizardPanel } from './index';

describe('Wizard', () => {
  it('renders a step', () => {
    const { container } = render(
      <Wizard>
        <Wizard.Step title="Step Nickname">
          <WizardPanel>
            <WizardPanel.Heading title="Title" subtitle="Subtitle" />
            Content
            <WizardPanel.Actions>
              <WizardPanel.ActionNext>Continue</WizardPanel.ActionNext>
            </WizardPanel.Actions>
          </WizardPanel>
        </Wizard.Step>
      </Wizard>
    );

    expect(container).toMatchSnapshot();
  });

  it('renders a step nickname correctly', () => {
    const { getByText } = render(
      <Wizard>
        <Wizard.Step title="A">test</Wizard.Step>
        <Wizard.Step title="B">test</Wizard.Step>
      </Wizard>
    );

    expect(getByText('A')).toBeInTheDocument();
    expect(getByText('B')).toBeInTheDocument();
  });

  it("doesn't render a nickname if header is false", () => {
    const { queryByText } = render(
      <Wizard header={false}>
        <Wizard.Step title="A">test</Wizard.Step>
        <Wizard.Step title="A">test</Wizard.Step>
      </Wizard>
    );

    expect(queryByText('A')).not.toBeInTheDocument();
    expect(queryByText('B')).not.toBeInTheDocument();
  });

  it('renders the header correctly', () => {
    const { container, getByText } = render(
      <Wizard header={false}>
        <Wizard.Step>
          <WizardPanel>
            <WizardPanel.Heading title="Title" subtitle="Subtitle" />
          </WizardPanel>
        </Wizard.Step>
      </Wizard>
    );

    expect(container.querySelector('header')).toBeInTheDocument();
    expect(getByText('Title')).toBeInTheDocument();
    expect(getByText('Subtitle')).toBeInTheDocument();
  });

  it('renders the content of a step', () => {
    const { getByText } = render(
      <Wizard header={false}>
        <Wizard.Step>
          <WizardPanel>
            Content
            <WizardPanel.ActionNext />
          </WizardPanel>
        </Wizard.Step>
      </Wizard>
    );

    expect(getByText('Content')).toBeInTheDocument();
  });

  it('does not render back/next buttons by default', () => {
    const { queryByText, queryByAriaLabel } = render(
      <Wizard header={false}>
        <Wizard.Step>
          <WizardPanel>Content</WizardPanel>
        </Wizard.Step>
      </Wizard>
    );

    expect(queryByText('Next')).not.toBeInTheDocument();
    expect(queryByAriaLabel('Go Back')).not.toBeInTheDocument();
  });

  it('renders a back/next buttons when included', () => {
    const { queryByText, queryByAriaLabel } = render(
      <Wizard header={false}>
        <Wizard.Step>
          <WizardPanel>
            <WizardPanel.ActionPrev />
            <WizardPanel.ActionNext />
          </WizardPanel>
        </Wizard.Step>
      </Wizard>
    );

    expect(queryByText('Next')).toBeInTheDocument();
    expect(queryByAriaLabel('Go Back')).toBeInTheDocument();
  });

  it("allows overriding the next button's text", () => {
    const { queryByText } = render(
      <Wizard header={false}>
        <Wizard.Step>
          <WizardPanel>
            <WizardPanel.ActionNext>Continue</WizardPanel.ActionNext>
          </WizardPanel>
        </Wizard.Step>
      </Wizard>
    );

    expect(queryByText('Continue')).toBeInTheDocument();
  });

  it('correctly sets and resets the step Status', () => {
    const WizardStepStatusSetter = () => {
      const { setCurrentStepStatus } = useWizardContext();
      return <button onClick={() => setCurrentStepStatus('FAILING')}>Set Step Status</button>;
    };

    const WizardStepStatusDisplay = () => {
      const { currentStepStatus } = useWizardContext();
      return <div>{currentStepStatus.toLowerCase()}</div>;
    };

    const { queryByText, getByAriaLabel } = render(
      <Wizard header={false}>
        <Wizard.Step>
          <WizardPanel>
            A
            <WizardStepStatusDisplay />
            <WizardStepStatusSetter />
            <WizardPanel.ActionNext>Continue</WizardPanel.ActionNext>
          </WizardPanel>
        </Wizard.Step>
        <Wizard.Step>
          B
          <WizardStepStatusDisplay />
          <WizardStepStatusSetter />
          <WizardPanel.ActionPrev />
        </Wizard.Step>
      </Wizard>
    );

    expect(queryByText('pending')).toBeInTheDocument();

    fireEvent.click(queryByText('Set Step Status'));
    expect(queryByText('failing')).toBeInTheDocument();

    fireEvent.click(queryByText('Continue'));
    expect(queryByText('pending')).toBeInTheDocument();
    expect(queryByText('failing')).not.toBeInTheDocument();

    fireEvent.click(queryByText('Set Step Status'));
    expect(queryByText('failing')).toBeInTheDocument();

    fireEvent.click(getByAriaLabel('Go Back'));
    expect(queryByText('pending')).toBeInTheDocument();
    expect(queryByText('failing')).not.toBeInTheDocument();
  });

  it('prev/next and start over buttons work correctly', () => {
    const { getByText, queryByText, getByAriaLabel } = render(
      <Wizard header={false}>
        <Wizard.Step>
          <WizardPanel>
            A
            <WizardPanel.Actions>
              <WizardPanel.ActionNext />
            </WizardPanel.Actions>
          </WizardPanel>
        </Wizard.Step>
        <Wizard.Step>
          <WizardPanel>
            B
            <WizardPanel.Actions>
              <WizardPanel.ActionPrev />
              <WizardPanel.ActionNext />
            </WizardPanel.Actions>
          </WizardPanel>
        </Wizard.Step>
        <Wizard.Step>
          <WizardPanel>
            C
            <WizardPanel.Actions>
              <WizardPanel.ActionPrev />
              <WizardPanel.ActionNext />
            </WizardPanel.Actions>
          </WizardPanel>
        </Wizard.Step>
        <Wizard.Step>
          <WizardPanel>
            D
            <WizardPanel.Actions>
              <WizardPanel.ActionStart />
            </WizardPanel.Actions>
          </WizardPanel>
        </Wizard.Step>
      </Wizard>
    );

    expect(getByText('A')).toBeInTheDocument();

    fireEvent.click(getByText('Next'));
    expect(queryByText('A')).not.toBeInTheDocument();
    expect(getByText('B')).toBeInTheDocument();

    fireEvent.click(getByText('Next'));
    expect(queryByText('B')).not.toBeInTheDocument();
    expect(getByText('C')).toBeInTheDocument();

    fireEvent.click(getByAriaLabel('Go Back'));
    expect(getByText('B')).toBeInTheDocument();
    expect(queryByText('C')).not.toBeInTheDocument();

    fireEvent.click(getByAriaLabel('Go Back'));
    expect(getByText('A')).toBeInTheDocument();
    expect(queryByText('B')).not.toBeInTheDocument();

    fireEvent.click(getByText('Next'));
    fireEvent.click(getByText('Next'));
    expect(queryByText('C')).toBeInTheDocument();

    fireEvent.click(getByText('Next'));
    expect(queryByText('D')).toBeInTheDocument();

    fireEvent.click(getByText('Start Over'));
    expect(queryByText('D')).not.toBeInTheDocument();
    expect(queryByText('A')).toBeInTheDocument();
  });

  it('correctly go to a specific step', () => {
    const { getByText, queryByText } = render(
      <Wizard header={false}>
        <Wizard.Step>
          <WizardPanel>
            A
            <WizardPanel.Actions>
              <WizardPanel.ActionGoToStep stepIndex={2} />
            </WizardPanel.Actions>
          </WizardPanel>
        </Wizard.Step>
        <Wizard.Step>
          <WizardPanel>
            B
            <WizardPanel.Actions>
              <WizardPanel.ActionPrev />
              <WizardPanel.ActionNext />
            </WizardPanel.Actions>
          </WizardPanel>
        </Wizard.Step>
        <Wizard.Step>
          <WizardPanel>
            C
            <WizardPanel.Actions>
              <WizardPanel.ActionPrev />
              <WizardPanel.ActionNext />
            </WizardPanel.Actions>
          </WizardPanel>
        </Wizard.Step>
        <Wizard.Step>
          <WizardPanel>
            D
            <WizardPanel.Actions>
              <WizardPanel.ActionStart />
            </WizardPanel.Actions>
          </WizardPanel>
        </Wizard.Step>
      </Wizard>
    );

    expect(getByText('A')).toBeInTheDocument();

    fireEvent.click(getByText('Continue'));
    expect(queryByText('A')).not.toBeInTheDocument();
    expect(getByText('C')).toBeInTheDocument();
  });

  it('allows updating the context data correctly', () => {
    const WizardDataConsumer = () => {
      const { data } = useWizardContext();
      return (
        <div>
          {data.text}-{Object.keys(data).length}
        </div>
      );
    };

    const WizardDataSetter = () => {
      const { setData } = useWizardContext();
      return <button onClick={() => setData({ text: 'B' })}>Set Data</button>;
    };

    const WizardDataUpdater = () => {
      const { updateData } = useWizardContext();
      return <button onClick={() => updateData({ test: 'test' })}>Update Data</button>;
    };

    const WizardDataResetter = () => {
      const { resetData } = useWizardContext();
      return <button onClick={resetData}>Reset Data</button>;
    };

    const { getByText } = render(
      <Wizard initialData={{ text: 'A' }} header={false}>
        <Wizard.Step>
          <WizardPanel>
            <WizardDataConsumer />
            <WizardDataSetter />
            <WizardDataUpdater />
            <WizardDataResetter />
          </WizardPanel>
        </Wizard.Step>
      </Wizard>
    );

    expect(getByText('A-1')).toBeInTheDocument();

    fireEvent.click(getByText('Set Data'));
    expect(getByText('B-1')).toBeInTheDocument();

    fireEvent.click(getByText('Update Data'));
    expect(getByText('B-2')).toBeInTheDocument();

    fireEvent.click(getByText('Reset Data'));
    expect(getByText('A-1')).toBeInTheDocument();
  });

  it('correctly  resets everything when  `reset` is called', () => {
    const WizardDataConsumer = () => {
      const { data } = useWizardContext();
      return <div>{data}</div>;
    };

    const WizardDataSetter = () => {
      const { setData } = useWizardContext();
      return <button onClick={() => setData('B')}>Set Data</button>;
    };

    const WizardResetter = () => {
      const { reset } = useWizardContext();
      return <button onClick={reset}>Reset</button>;
    };

    const { getByText } = render(
      <Wizard initialData="A" header={false}>
        <Wizard.Step>
          <WizardPanel>
            First
            <WizardDataSetter />
            <WizardDataConsumer />
            <WizardPanel.Actions>
              <WizardPanel.ActionNext />
            </WizardPanel.Actions>
          </WizardPanel>
        </Wizard.Step>
        <Wizard.Step>
          <WizardPanel>
            Second
            <WizardResetter />
            <WizardDataConsumer />
          </WizardPanel>
        </Wizard.Step>
      </Wizard>
    );

    expect(getByText('A')).toBeInTheDocument();
    expect(getByText('First')).toBeInTheDocument();

    fireEvent.click(getByText('Set Data'));
    fireEvent.click(getByText('Next'));
    expect(getByText('B')).toBeInTheDocument();
    expect(getByText('Second')).toBeInTheDocument();

    fireEvent.click(getByText('Reset'));
    expect(getByText('A')).toBeInTheDocument();
    expect(getByText('First')).toBeInTheDocument();
  });
});
