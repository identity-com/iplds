import { CID } from 'ipfs-http-client';
import { Link, Recipient } from '../types/types';

const collectCIDsFromArray = function* (
  value: Record<string, unknown>[],
  path: (string | number)[],
  ivResolver: (cid: CID) => Uint8Array,
): Iterable<Link> {
  for (const [index, element] of value.entries()) {
    const elementPath = [...path, index];
    const cid = CID.asCID(element);
    if (cid) {
      yield { path: elementPath.join('/'), iv: ivResolver(cid), cid };
    } else if (typeof element === 'object') {
      yield* links(element, ivResolver, elementPath);
    }
  }
};

const collectCIDsFromNested = function* (
  value: Record<string, unknown> | undefined,
  path: (string | number)[],
  ivResolver: (cid: CID) => Uint8Array,
): Iterable<Link> {
  const cid = CID.asCID(value);
  if (cid) {
    yield { path: path.join('/'), iv: ivResolver(cid), cid };
  } else {
    yield* links(value, ivResolver, path);
  }
};

export const links = function* (
  source: Record<string, unknown> | undefined,
  ivResolver: (cid: CID) => Uint8Array,
  base: (string | number)[] = [],
): Iterable<Link> {
  /* eslint-disable-next-line eqeqeq, curly */
  if (source == null) return;
  /* eslint-disable-next-line curly */
  if (source instanceof Uint8Array) return;
  for (const [key, value] of Object.entries(source)) {
    const path = [...base, key];
    /* eslint-disable-next-line eqeqeq */
    if (value != null && typeof value === 'object') {
      if (Array.isArray(value)) {
        yield* collectCIDsFromArray(value, path, ivResolver);
      } else {
        yield* collectCIDsFromNested(value as Record<string, unknown>, path, ivResolver);
      }
    }
  }
};

export type ComplexObject = null | { [key: string]: ComplexObject };

export const buildLinkObject = (links: Link[]): ComplexObject => {
  const result: ComplexObject = {};
  for (const link of links) {
    createPath(result, link.path.split('/'), link.cid);
  }
  // eslint-disable-next-line @typescript-eslint/no-unsafe-return
  return result;
};

const createPath = (obj: Record<string, unknown>, path: string[], value: unknown = null): void => {
  let current = obj;
  while (path.length > 1) {
    const [head, ...tail] = path;
    path = tail;
    if (current[head] === undefined) {
      current[head] = Object.create(null);
    }
    current = current[head] as Record<string, unknown>;
  }
  current[path[0]] = value;
};

type AllValues<T extends Record<PropertyKey, PropertyKey>> = {
  [P in keyof T]: { key: P; value: T[P] };
}[keyof T];

type InvertResult<T extends Record<PropertyKey, PropertyKey>> = {
  [P in AllValues<T>['value']]: Extract<AllValues<T>, { value: P }>['key'];
};

export const invertSimpleObject = <T extends Record<PropertyKey, PropertyKey>>(obj: T): InvertResult<T> => {
  const result: Record<PropertyKey, PropertyKey> = {};
  const keys = Object.keys(obj);
  for (const key of keys) {
    const newKey = obj[key];
    result[newKey] = key;
  }

  return result as InvertResult<T>;
};

export const cloneRecipient = (recipient: Recipient): Recipient =>
  [{ ...recipient[0] }, { ...recipient[1] }, recipient[2].slice(0), recipient[3].map(cloneRecipient)] as Recipient;

export const cloneReplacingCIDs = <T>(source: T, cids: Map<string, CID>): T => {
  if (Array.isArray(source)) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return source.map((item) => cloneReplacingCIDs(item, cids)) as unknown as T;
  }

  if (source instanceof Date) {
    return new Date(source.getTime()) as unknown as T;
  }

  if (source instanceof CID) {
    const newCID = cids.get(source.toString());
    if (!newCID) {
      throw new Error(`Mapping for ${source.toString()} is absent`);
    }

    return newCID as unknown as T;
  }

  if (source && typeof source === 'object') {
    return Object.getOwnPropertyNames(source).reduce((o, prop) => {
      Object.defineProperty(o, prop, Object.getOwnPropertyDescriptor(source, prop)!);

      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      o[prop] = cloneReplacingCIDs(source as { [key: string]: any }[prop], cids);

      // eslint-disable-next-line @typescript-eslint/no-unsafe-return
      return o;
    }, Object.create(Object.getPrototypeOf(source))) as T;
  }

  return source;
};
