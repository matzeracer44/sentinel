declare module 'classic-level' {
  export interface LevelOptions {
    valueEncoding?: string;
    createIfMissing?: boolean;
    errorIfExists?: boolean;
  }

  export interface IteratorOptions {
    gt?: string;
    gte?: string;
    lt?: string;
    lte?: string;
    reverse?: boolean;
    limit?: number;
  }

  export interface LevelIterator<K = string, V = unknown> extends AsyncIterableIterator<[K, V]> {
    close(): Promise<void>;
  }

  export class ClassicLevel<K = string, V = unknown> {
    constructor(location: string, options?: LevelOptions);
    open(): Promise<void>;
    close(): Promise<void>;
    put(key: K, value: V): Promise<void>;
    get<T = V>(key: K): Promise<T>;
    del(key: K): Promise<void>;
    iterator<T = V>(options?: IteratorOptions): LevelIterator<K, T>;
  }

  export type Level<K = string, V = unknown> = ClassicLevel<K, V>;
}
