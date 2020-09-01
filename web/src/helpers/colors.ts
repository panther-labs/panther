interface StringToHSL {
  str: string;
  hue?: [number, number];
  saturation?: [number, number];
  lightness?: [number, number];
}

/**
 * Restricts a given number in the range specified
 */
const restrictToRange = (number, min, max) => {
  const diff = max - min;
  const x = ((number % diff) + diff) % diff;
  return x + min;
};

const stringToHSL = ({
  str,
  hue = [0, 360],
  saturation = [75, 100],
  lightness = [40, 60],
}: StringToHSL) => {
  if (!str.length) {
    return `hsl(0,0,0)`;
  }

  /* eslint-disable no-bitwise */
  let hash = 0;
  str.split('').forEach((letter, index) => {
    hash = str.charCodeAt(index) + ((hash << 5) - hash);
    hash &= hash;
  });
  /* eslint-enable no-bitwise */

  const h = restrictToRange(hash, hue[0], hue[1]);
  const s = restrictToRange(hash, saturation[0], saturation[1]);
  const l = restrictToRange(hash, lightness[0], lightness[1]);

  return `hsl(${h}, ${s}%, ${l}%)`;
};

export const stringToPaleColor = (str: string) =>
  stringToHSL({ str, saturation: [20, 50], lightness: [30, 80] });
