import faker from 'faker';

/**
 * Selects a random element from an array
 * @param array An array of items
 */
export function randomFromArray<T>(array: T[] | ReadonlyArray<T>) {
  return array[faker.random.number({ min: 0, max: array.length - 1, precision: 1 })];
}

/**
 * Generates a random array of elements through a single item-generating function
 * @param func A function that generates an item
 * @param min The min length of the random array
 * @param max The max length of the random array
 */
export function generateRandomArray<T>(func: (index: number) => T, min = 0, max = 10) {
  const randomArrayLength = faker.random.number({ min, max, precision: 1 });
  return [...Array(randomArrayLength)].map((_, index) => func(index));
}
