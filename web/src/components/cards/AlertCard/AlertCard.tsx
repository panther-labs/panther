import React from 'react';
import { AlertTypesEnum } from 'Generated/schema';
import PolicyAlertCard, { PolicyAlertCardProps } from 'Components/cards/AlertCard/PolicyAlertCard';
import RuleAlertCard, { RuleAlertCardProps } from 'Components/cards/AlertCard/RuleAlertCard';

type AlertCardProps = PolicyAlertCardProps | RuleAlertCardProps;

const AlertCard: React.FC<AlertCardProps> = props => {
  switch (props.alert.type) {
    case AlertTypesEnum.Policy:
      return <PolicyAlertCard {...props} />;

    case AlertTypesEnum.Rule:
    case AlertTypesEnum.RuleError:
    default:
      return <RuleAlertCard {...props} />;
  }
};

export default AlertCard;
