declare module 'kitx' {
  export function md5(input: Buffer | string, encoding?: string): string;
  export function sha1(input: string, key: string, encoding?: string): string;
}
