import React from 'react';
import { render, fireEvent } from 'test-utils';
import { useWizardContext, Wizard, WizardPanelWrapper } from './index';

describe('Wizard', () => {
  it('renders a step', () => {
    const { container } = render(
      <Wizard>
        <Wizard.Step title="Step Nickname">
          <WizardPanelWrapper>
            <WizardPanelWrapper.Content>
              <WizardPanelWrapper.Heading title="Title" subtitle="Subtitle" />
              Content
              <WizardPanelWrapper.Actions>
                <WizardPanelWrapper.ActionNext>Continue</WizardPanelWrapper.ActionNext>
              </WizardPanelWrapper.Actions>
            </WizardPanelWrapper.Content>
          </WizardPanelWrapper>
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
          <WizardPanelWrapper>
            <WizardPanelWrapper.Content>
              <WizardPanelWrapper.Heading title="Title" subtitle="Subtitle" />
            </WizardPanelWrapper.Content>
          </WizardPanelWrapper>
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
          <WizardPanelWrapper>
            <WizardPanelWrapper.Content>
              Content
              <WizardPanelWrapper.ActionNext />
            </WizardPanelWrapper.Content>
          </WizardPanelWrapper>
        </Wizard.Step>
      </Wizard>
    );

    expect(getByText('Content')).toBeInTheDocument();
  });

  it('does not render back/next buttons by default', () => {
    const { queryByText, queryByAriaLabel } = render(
      <Wizard header={false}>
        <Wizard.Step>
          <WizardPanelWrapper>
            <WizardPanelWrapper.Content>Content</WizardPanelWrapper.Content>
          </WizardPanelWrapper>
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
          <WizardPanelWrapper>
            <WizardPanelWrapper.Content>
              <WizardPanelWrapper.ActionPrev />
              <WizardPanelWrapper.ActionNext />
            </WizardPanelWrapper.Content>
          </WizardPanelWrapper>
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
          <WizardPanelWrapper>
            <WizardPanelWrapper.Content>
              <WizardPanelWrapper.ActionNext>Continue</WizardPanelWrapper.ActionNext>
            </WizardPanelWrapper.Content>
          </WizardPanelWrapper>
        </Wizard.Step>
      </Wizard>
    );

    expect(queryByText('Continue')).toBeInTheDocument();
  });

  it('prev/next buttons work correctly', () => {
    const { getByText, queryByText, getByAriaLabel } = render(
      <Wizard header={false}>
        <Wizard.Step>
          <WizardPanelWrapper>
            <WizardPanelWrapper.Content>
              A
              <WizardPanelWrapper.Actions>
                <WizardPanelWrapper.ActionNext />
              </WizardPanelWrapper.Actions>
            </WizardPanelWrapper.Content>
          </WizardPanelWrapper>
        </Wizard.Step>
        <Wizard.Step>
          <WizardPanelWrapper>
            <WizardPanelWrapper.Content>
              B
              <WizardPanelWrapper.Actions>
                <WizardPanelWrapper.ActionPrev />
                <WizardPanelWrapper.ActionNext />
              </WizardPanelWrapper.Actions>
            </WizardPanelWrapper.Content>
          </WizardPanelWrapper>
        </Wizard.Step>
        <Wizard.Step>
          <WizardPanelWrapper>
            <WizardPanelWrapper.Content>
              C
              <WizardPanelWrapper.Actions>
                <WizardPanelWrapper.ActionPrev />
              </WizardPanelWrapper.Actions>
            </WizardPanelWrapper.Content>
          </WizardPanelWrapper>
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
          <WizardPanelWrapper>
            <WizardPanelWrapper.Content>
              <WizardDataConsumer />
              <WizardDataSetter />
              <WizardDataUpdater />
              <WizardDataResetter />
            </WizardPanelWrapper.Content>
          </WizardPanelWrapper>
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
          <WizardPanelWrapper>
            <WizardPanelWrapper.Content>
              First
              <WizardDataSetter />
              <WizardDataConsumer />
              <WizardPanelWrapper.Actions>
                <WizardPanelWrapper.ActionNext />
              </WizardPanelWrapper.Actions>
            </WizardPanelWrapper.Content>
          </WizardPanelWrapper>
        </Wizard.Step>
        <Wizard.Step>
          <WizardPanelWrapper>
            <WizardPanelWrapper.Content>
              Second
              <WizardResetter />
              <WizardDataConsumer />
            </WizardPanelWrapper.Content>
          </WizardPanelWrapper>
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
