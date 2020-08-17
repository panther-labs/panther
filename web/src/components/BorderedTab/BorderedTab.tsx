import React from 'react';
import { PseudoBox, PseudoBoxProps } from 'pouncejs';

/**
 * These props are automatically passed by `TabList` and not by the developer
 */
interface BorderedTabProps {
  /** Whether the tab is selected */
  isSelected: boolean;
  /** Whether the tab is focused */
  isFocused: boolean;

  children: React.ReactNode;
}

const BorderedTab: React.FC<BorderedTabProps> = ({ isSelected, isFocused, children }) => {
  const selectedColor = 'blue-400';
  const focusedColor = 'navyblue-300';

  let borderColor: PseudoBoxProps['borderColor'];
  if (isSelected) {
    borderColor = selectedColor;
  } else if (isFocused) {
    borderColor = focusedColor;
  } else {
    borderColor = 'transparent';
  }

  return (
    <PseudoBox
      mr={8}
      borderBottom="3px solid"
      zIndex={5}
      py={4}
      transition="border-color 200ms cubic-bezier(0.0, 0, 0.2, 1) 0ms"
      borderColor={borderColor}
      _hover={{
        borderColor: !isSelected ? focusedColor : undefined,
      }}
    >
      {children}
    </PseudoBox>
  );
};

export default React.memo(BorderedTab);
